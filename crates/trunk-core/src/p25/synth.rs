//! A synthetic P25 Phase 1 transmitter, for tests and `tool p25synth`: the
//! frames of a call (header, LDUs, terminator) with its voice encrypted as a
//! radio would send it, C4FM-modulated. Each encoder here is the inverse of
//! a decoder in this crate (the frame tables, `decode_hdu`,
//! `decode_ldu1_lc`, `decode_ldu2_es`, `imbe_header_decode`), so a decode of
//! its output checks the two against each other, and what they were checked
//! against is the real recordings the decoders came from. The cipher is the
//! one [`crate::crypto::p25`] decrypts with (itself checked against the
//! standard), so a call sent here and decrypted again shows the whole path
//! from IQ to audio works, not that it agrees with a radio.

use num_complex::Complex32;

use super::fec::{golay23_encode, golay24_encode, hamming15_encode, hamming1063_parity, rs_encode};
use super::frame::{encode_nid, frame_dibits, HDU, LDU1, LDU2, SYNC_BITS, TDU};
use super::voice::{pngen, ALGID_CLEAR};
use crate::crypto::p25::{next_mi, CryptError, Keystream};
use crate::tables::{HDU_CODEWORD_BITS, LDU_LS_DATA_BITS, VOICE_CODEWORD_BITS};

/// A frame as raw bits from its sync, status symbols in place (what the
/// receiver's tables index): sync and NID filled in, the rest zero.
fn blank(nac: u16, duid: u8) -> Vec<u8> {
    let n = frame_dibits(duid);
    let mut raw = vec![0u8; 2 * n];
    // Status symbols: every 36th dibit.
    for p in (35..n).step_by(36) {
        raw[2 * p + 1] = 1;
    }
    let nid = encode_nid(nac, duid);
    let data = SYNC_BITS.iter().copied().chain((0..64).map(|i| ((nid >> (63 - i)) & 1) as u8));
    for (b, v) in data.enumerate() {
        let d = b / 2;
        raw[2 * (d + d / 35) + b % 2] = v;
    }
    raw
}

fn dibits_of(raw: &[u8]) -> Vec<u8> {
    raw.chunks(2).map(|c| c[0] << 1 | c[1]).collect()
}

/// Bytes as 6-bit symbols, MSB first.
fn hexbits(bytes: &[u8]) -> Vec<u8> {
    let bits: Vec<u8> = bytes.iter().flat_map(|b| (0..8).rev().map(move |i| b >> i & 1)).collect();
    bits.chunks(6).map(|c| (0..6).fold(0u8, |v, i| v << 1 | c.get(i).copied().unwrap_or(0))).collect()
}

/// The 36 Golay(18,6) words of an HDU's hexbits.
fn put_hdu(raw: &mut [u8], hb: &[u8; 63]) {
    for i in 0..36 {
        let cw = golay24_encode(hb[27 + i] as u32);
        for b in 0..18 {
            raw[HDU_CODEWORD_BITS[18 * i + b] as usize] = (cw >> (17 - b) & 1) as u8;
        }
    }
}

/// The 24 Hamming(10,6) words of an LDU's link control or encryption sync hexbits.
fn put_ldu_words(raw: &mut [u8], hb: &[u8; 63]) {
    for i in 0..24 {
        let d = hb[39 + i];
        let w = (d as u32) << 4 | hamming1063_parity(d as u32) as u32;
        for b in 0..10 {
            raw[LDU_LS_DATA_BITS[10 * i + b] as usize] = (w >> (9 - b) & 1) as u8;
        }
    }
}

/// The 144 coded bits of an IMBE frame from its 88 information bits: the
/// inverse of `imbe_header_decode` (whose indexing it keeps).
#[allow(clippy::needless_range_loop)]
pub fn imbe_codeword(d: &[u8; 88]) -> [u8; 144] {
    let mut u = [0u32; 8];
    let mut p = 0;
    for (k, w) in [12, 12, 12, 12, 11, 11, 11, 7].into_iter().enumerate() {
        for _ in 0..w {
            u[k] = u[k] << 1 | d[p] as u32;
            p += 1;
        }
    }
    let mut cw = [0u8; 144];
    let mut put = |at: usize, v: u32, n: usize| {
        for i in 0..n {
            cw[at + i] = (v >> (n - 1 - i) & 1) as u8;
        }
    };
    put(0, golay23_encode(u[0]), 23);
    let mut pr = u[0] << 4;
    for k in 1..=3 {
        let m = pngen(&mut pr, 23);
        put(23 * k, golay23_encode(u[k]) ^ m, 23);
    }
    for k in 4..=6 {
        let m = pngen(&mut pr, 15);
        put(92 + (k - 4) * 15, hamming15_encode(u[k]) ^ m, 15);
    }
    put(137, u[7], 7);
    cw
}

fn put_voice(raw: &mut [u8], frames: &[[u8; 88]; 9]) {
    for (f, d) in frames.iter().enumerate() {
        let cw = imbe_codeword(d);
        for (j, &b) in cw.iter().enumerate() {
            raw[VOICE_CODEWORD_BITS[f * 144 + j] as usize] = b;
        }
    }
}

/// A header data unit (call start): the first superframe's MI, the cipher and key id, the talkgroup.
pub fn hdu(nac: u16, mi: &[u8; 9], algid: u8, kid: u16, tgid: u16) -> Vec<u8> {
    let mut raw = blank(nac, HDU);
    let mut bytes = mi.to_vec();
    bytes.extend([0, algid, (kid >> 8) as u8, kid as u8, (tgid >> 8) as u8, tgid as u8]);
    let mut hb = [0u8; 63];
    hb[27..47].copy_from_slice(&hexbits(&bytes));
    rs_encode(&mut hb, 16);
    put_hdu(&mut raw, &hb);
    dibits_of(&raw)
}

/// LDU1: link control (group voice, `svc` service options) and 9 voice frames.
pub fn ldu1(nac: u16, svc: u8, tgid: u16, source: u32, voice: &[[u8; 88]; 9]) -> Vec<u8> {
    let mut raw = blank(nac, LDU1);
    let lc = [0, 0, svc, 0, (tgid >> 8) as u8, tgid as u8, (source >> 16) as u8, (source >> 8) as u8, source as u8];
    let mut hb = [0u8; 63];
    hb[39..51].copy_from_slice(&hexbits(&lc));
    rs_encode(&mut hb, 12);
    put_ldu_words(&mut raw, &hb);
    put_voice(&mut raw, voice);
    dibits_of(&raw)
}

/// LDU2: the encryption sync (the next superframe's MI, the cipher, the key id) and 9 voice frames.
pub fn ldu2(nac: u16, mi_next: &[u8; 9], algid: u8, kid: u16, voice: &[[u8; 88]; 9]) -> Vec<u8> {
    let mut raw = blank(nac, LDU2);
    let mut bytes = mi_next.to_vec();
    bytes.extend([algid, (kid >> 8) as u8, kid as u8]);
    let mut hb = [0u8; 63];
    hb[39..55].copy_from_slice(&hexbits(&bytes));
    rs_encode(&mut hb, 8);
    put_ldu_words(&mut raw, &hb);
    put_voice(&mut raw, voice);
    dibits_of(&raw)
}

/// A terminator without link control.
pub fn tdu(nac: u16) -> Vec<u8> {
    dibits_of(&blank(nac, TDU))
}

/// How a call is encrypted.
#[derive(Clone, Debug)]
pub struct Crypt {
    pub algid: u8,
    pub kid: u16,
    pub key: Vec<u8>,
    /// The first superframe's MI (the header's).
    pub mi: [u8; 9],
}

/// Where a receiver "joins" a call: what of its start is not sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Start {
    /// The header, then everything.
    Header,
    /// Mid-call, at an LDU1.
    Ldu1,
    /// Mid-call, at an LDU2 (the first LDU1 is not sent).
    Ldu2,
}

/// A call: `superframes` of an LDU1 and an LDU2 each.
#[derive(Clone, Debug)]
pub struct Call {
    pub nac: u16,
    pub tgid: u16,
    pub source: u32,
    pub crypt: Option<Crypt>,
    pub superframes: usize,
    pub start: Start,
}

/// Voice frame `n` of a call: 88 bits that vocode as a voiced frame (a pitch in range, the
/// rest varying with `n`).
pub fn imbe(n: usize) -> [u8; 88] {
    let mut x = 0x9e37_79b9u32 ^ (n as u32).wrapping_mul(0x85eb_ca6b);
    let mut d: [u8; 88] = std::array::from_fn(|_| {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        (x & 1) as u8
    });
    let pitch = 40 + (n * 7) % 120;
    for (i, b) in d[..8].iter_mut().enumerate() {
        *b = (pitch >> (7 - i) & 1) as u8;
    }
    d
}

impl Call {
    /// The call's frames as dibits, in order, ending with a terminator. Voice frame `n` is `voice(n)`
    /// (clear), encrypted here when the call is.
    pub fn frames(&self, voice: impl Fn(usize) -> [u8; 88]) -> Result<Vec<Vec<u8>>, CryptError> {
        let (algid, kid) = self.crypt.as_ref().map_or((ALGID_CLEAR, 0), |c| (c.algid, c.kid));
        // Encrypted voice carries the "encrypted" service option in its (clear) link control.
        let svc = if self.crypt.is_some() { 0x40 } else { 0 };
        let mut out = Vec::new();
        let mut mi = self.crypt.as_ref().map_or([0u8; 9], |c| c.mi);
        if self.start == Start::Header {
            out.push(hdu(self.nac, &mi, algid, kid, self.tgid));
        }
        for s in 0..self.superframes {
            let stream = self.crypt.as_ref().map(|c| Keystream::new(c.algid, &c.key, &mi)).transpose()?;
            let frames = |ldu2: bool| -> [[u8; 88]; 9] {
                std::array::from_fn(|k| {
                    let mut d = voice(18 * s + if ldu2 { 9 } else { 0 } + k);
                    if let Some(st) = &stream {
                        st.apply(ldu2, k, &mut d);
                    }
                    d
                })
            };
            if !(s == 0 && self.start == Start::Ldu2) {
                out.push(ldu1(self.nac, svc, self.tgid, self.source, &frames(false)));
            }
            let next = if self.crypt.is_some() { next_mi(&mi) } else { [0; 9] };
            out.push(ldu2(self.nac, &next, algid, kid, &frames(true)));
            mi = next;
        }
        out.push(tdu(self.nac));
        Ok(out)
    }
}

/// C4FM at 4800 baud, `fs` samples per second, `offset_hz` off the channel centre: ±600 Hz and
/// ±1800 Hz for the dibits 00 / 10 and 01 / 11, frequency pulses smoothed over half a symbol.
pub fn modulate(dibits: &[u8], fs: f64, offset_hz: f64, amp: f32, phase: &mut f64) -> Vec<Complex32> {
    const BAUD: f64 = 4800.0;
    const UNIT: f64 = 600.0;
    let sps = fs / BAUD;
    let n = (dibits.len() as f64 * sps) as usize;
    let w = ((sps / 2.0).round() as usize).max(1);
    let level = |k: usize| {
        UNIT * match dibits[k.min(dibits.len() - 1)] & 3 {
            0b01 => 3.0,
            0b00 => 1.0,
            0b10 => -1.0,
            _ => -3.0,
        }
    };
    let raw: Vec<f64> = (0..n).map(|i| level((i as f64 / sps) as usize)).collect();
    let mut acc = 0.0;
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        acc += raw[i];
        if i >= w {
            acc -= raw[i - w];
        }
        let f = acc / w.min(i + 1) as f64;
        *phase += 2.0 * std::f64::consts::PI * (offset_hz + f) / fs;
        out.push(Complex32::from_polar(amp, *phase as f32));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dsp::Symbol;
    use crate::p25::frame::{Framer, FramerOptions};
    use crate::p25::voice::{decode_hdu, decode_ldu1_lc, decode_ldu2_es, imbe_params_to_bits, ldu_imbe};

    fn frames_of(dibits: &[u8]) -> Vec<crate::p25::Frame> {
        let mut fr = Framer::new(FramerOptions::default());
        let mut out = Vec::new();
        for (i, &dibit) in dibits.iter().enumerate() {
            fr.push(&Symbol { dibit, sample: i as f64, rel_hi: 1.0, rel_lo: 1.0 }, &mut out);
        }
        out
    }

    const KEY: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    const MI: [u8; 9] = [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0];

    fn call(crypt: bool, start: Start) -> Call {
        Call { nac: 0x293, tgid: 1001, source: 4_567_890, crypt: crypt.then(|| Crypt { algid: 0x81, kid: 7, key: KEY.to_vec(), mi: MI }), superframes: 3, start }
    }

    /// What goes in comes out: every field of every frame, read back by the real decoders.
    #[test]
    fn a_clear_call_reads_back_field_for_field() {
        let c = call(false, Start::Header);
        let sent: Vec<u8> = c.frames(imbe).unwrap().into_iter().flatten().collect();
        let got = frames_of(&sent);
        // HDU, 3 × (LDU1, LDU2); the last frame (the TDU) is read when the stream goes on, so pad it.
        let mut padded = sent.clone();
        padded.extend(std::iter::repeat_n(0b01u8, 100));
        let got = if got.len() < 8 { frames_of(&padded) } else { got };
        let duids: Vec<u8> = got.iter().map(|f| f.nid.duid).collect();
        assert_eq!(duids, [HDU, LDU1, LDU2, LDU1, LDU2, LDU1, LDU2, TDU]);
        assert!(got.iter().all(|f| f.nid.nac == 0x293 && f.complete));
        let h = decode_hdu(&got[0].raw).expect("an HDU");
        assert_eq!((h.es.algid, h.es.keyid, h.tgid), (0x80, 0, 1001));
        let lc = decode_ldu1_lc(&got[1].raw).expect("link control");
        assert_eq!((lc.lco, lc.tgid, lc.source, lc.svc_opts), (0, Some(1001), Some(4_567_890), Some(0)));
        let es = decode_ldu2_es(&got[2].raw).expect("an encryption sync");
        assert_eq!((es.algid, es.keyid), (0x80, 0));
        for (n, f) in got[1..7].iter().enumerate() {
            let params = ldu_imbe(f, false);
            for (k, p) in params.iter().enumerate() {
                assert_eq!(p.errs, 0);
                assert_eq!(imbe_params_to_bits(&p.u)[..], imbe(9 * n + k)[..], "LDU {n} frame {k}");
            }
        }
    }

    #[test]
    fn an_encrypted_call_carries_its_header_and_syncs_and_its_voice_is_not_the_clear_voice() {
        let c = call(true, Start::Header);
        let mut sent: Vec<u8> = c.frames(imbe).unwrap().into_iter().flatten().collect();
        sent.extend(std::iter::repeat_n(0b01u8, 100));
        let got = frames_of(&sent);
        let h = decode_hdu(&got[0].raw).unwrap();
        assert_eq!((h.es.algid, h.es.keyid, h.es.mi), (0x81, 7, MI));
        let lc = decode_ldu1_lc(&got[1].raw).unwrap();
        assert_eq!(lc.svc_opts, Some(0x40), "clear link control that says encrypted");
        // Each LDU2's sync is the next superframe's MI.
        let mut mi = MI;
        for s in 0..3 {
            mi = crate::crypto::p25::next_mi(&mi);
            let es = decode_ldu2_es(&got[2 + 2 * s].raw).unwrap();
            assert_eq!((es.algid, es.keyid, es.mi), (0x81, 7, mi), "superframe {s}");
        }
        let p = ldu_imbe(&got[1], false);
        assert_ne!(imbe_params_to_bits(&p[0].u)[..], imbe(0)[..]);
        // And with the key, the header's MI and the standard's layout it is the clear voice again.
        let ks = Keystream::new(0x81, &KEY, &MI).unwrap();
        let mut b = imbe_params_to_bits(&p[3].u);
        ks.apply(false, 3, &mut b);
        assert_eq!(b[..], imbe(3)[..]);
    }

    #[test]
    fn a_call_can_start_late() {
        for (start, first) in [(Start::Ldu1, LDU1), (Start::Ldu2, LDU2)] {
            let mut sent: Vec<u8> = call(true, start).frames(imbe).unwrap().into_iter().flatten().collect();
            sent.extend(std::iter::repeat_n(0b01u8, 100));
            let got = frames_of(&sent);
            assert_eq!(got[0].nid.duid, first, "{start:?}");
            assert!(got.iter().all(|f| f.nid.duid != HDU));
        }
    }

    #[test]
    fn a_key_of_the_wrong_size_is_an_error() {
        let mut c = call(true, Start::Header);
        c.crypt.as_mut().unwrap().key = vec![0; 5];
        assert!(c.frames(imbe).is_err());
    }
}
