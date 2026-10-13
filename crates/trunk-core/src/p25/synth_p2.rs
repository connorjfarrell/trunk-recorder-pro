//! A synthetic P25 Phase 2 (TDMA) transmitter, the companion of [`super::synth`]: the 12 timeslots
//! of each 360 ms superframe on one 6000-baud H-DQPSK channel, one logical channel carrying a call
//! (a MAC_PTT on its SACCH, then 4V, 4V, 4V, 4V and 2V voice bursts with the ESS spread over them,
//! then a MAC_END_PTT), the other idle. Each encoder is the inverse of a decoder in
//! [`super::phase2`], so a decode checks the two against each other; the cipher and its layout are
//! [`crate::crypto::p25`]'s (checked against TIA-102.AAAD-B's examples).

use num_complex::Complex32;

use super::fec::rs_encode;
use super::phase2::{
    crc12, xor_mask, BURST_2V, BURST_4V, BURST_SACCH_S, MAC_END_PTT, MAC_PTT, SLOT_CHANNEL, SLOT_DIBITS, SYMBOL_RATE,
};
use super::synth::{Crypt, Start};
use super::voice::ALGID_CLEAR;
use crate::ambe::encode_vcw;
use crate::crypto::p25::{next_mi, CryptError, Keystream};
use crate::dsp::filters;
use crate::tables::{DUID_LOOKUP, ISCH_CODEWORDS};

/// The S-ISCH, as 20 dibits.
fn sync_dibits() -> [u8; 20] {
    const SYNC: u64 = 0x57_5D57_F7FF;
    std::array::from_fn(|i| (SYNC >> (2 * (19 - i)) & 3) as u8)
}

/// The ISCH of superframe slot `slot`: the sync word in slots 2, 3, 6, 7, 10, 11, else the I-ISCH
/// that says which slot it is (channel in bits 6..5, location in 4..3 of its value).
fn isch(slot: usize) -> [u8; 20] {
    if matches!(slot, 2 | 3 | 6 | 7 | 10 | 11) {
        return sync_dibits();
    }
    let value = ((slot % 4) << 5 | (slot / 4) << 3) as i8;
    let cw = ISCH_CODEWORDS.iter().find(|&&(_, v)| v == value).map(|&(cw, _)| cw).expect("an I-ISCH codeword");
    std::array::from_fn(|i| (cw >> (2 * (19 - i)) & 3) as u8)
}

/// The 4 DUID dibits of a burst type: the codeword at the middle of its decoding sphere.
fn duid(t: i8) -> [u8; 4] {
    let near = |v: usize| (0..8).filter(|k| DUID_LOOKUP[v ^ (1 << k)] == t).count();
    let v = (0..256).filter(|&v| DUID_LOOKUP[v] == t).max_by_key(|&v| near(v)).expect("a DUID");
    std::array::from_fn(|i| (v >> (2 * (3 - i)) & 3) as u8)
}

const DUID_POS: [usize; 4] = [10, 47, 132, 169];

/// A burst: 170 dibits, unscrambled so far, with its DUID in.
fn burst(t: i8) -> [u8; 170] {
    let mut x = [0u8; 170];
    for (p, d) in DUID_POS.iter().zip(duid(t)) {
        x[*p] = d;
    }
    x
}

/// A slot's 180 dibits: its ISCH, then the burst scrambled (its DUID is not).
fn slot_packet(slot: usize, x: &[u8; 170], mask: &[u8]) -> [u8; SLOT_DIBITS] {
    let mut p = [0u8; SLOT_DIBITS];
    p[..20].copy_from_slice(&isch(slot));
    for i in 10..170 {
        p[10 + i] = if DUID_POS.contains(&i) { x[i] } else { x[i] ^ mask[slot * SLOT_DIBITS + i] };
    }
    p
}

fn put_hexbit(x: &mut [u8; 170], at: usize, h: u8) {
    x[at] = h >> 4 & 3;
    x[at + 1] = h >> 2 & 3;
    x[at + 2] = h & 3;
}

/// The 44 hexbits of an ESS for `algid`, `kid` and the next superframe's `mi`: 16 of information
/// (sent 4 to each 4V burst: ESS-B), 28 of parity (the 2V burst: ESS-A).
fn ess(algid: u8, kid: u16, mi: &[u8; 9]) -> ([u8; 16], [u8; 28]) {
    let mut bytes = vec![algid, (kid >> 8) as u8, kid as u8];
    bytes.extend(mi);
    let bits: Vec<u8> = bytes.iter().flat_map(|b| (0..8).rev().map(move |i| b >> i & 1)).collect();
    let mut cw = [0u8; 63];
    for (i, c) in bits.chunks(6).enumerate() {
        cw[19 + i] = c.iter().fold(0, |v, &b| v << 1 | b);
    }
    rs_encode(&mut cw, 28);
    (cw[19..35].try_into().unwrap(), cw[35..63].try_into().unwrap())
}

/// A 4V burst: four voice frames and ESS-B segment `b` (0 to 3).
fn burst_4v(frames: &[[u8; 49]; 4], ess_b: &[u8; 16], b: usize) -> [u8; 170] {
    let mut x = burst(BURST_4V);
    for (k, at) in [11usize, 48, 96, 133].into_iter().enumerate() {
        x[at..at + 36].copy_from_slice(&encode_vcw(&frames[k]));
    }
    for h in 0..4 {
        put_hexbit(&mut x, 84 + 3 * h, ess_b[4 * b + h]);
    }
    x
}

/// A 2V burst: two voice frames and the ESS-A parity.
fn burst_2v(frames: &[[u8; 49]; 2], ess_a: &[u8; 28]) -> [u8; 170] {
    let mut x = burst(BURST_2V);
    for (k, at) in [11usize, 48].into_iter().enumerate() {
        x[at..at + 36].copy_from_slice(&encode_vcw(&frames[k]));
    }
    let mut j = 84;
    for (i, &h) in ess_a.iter().enumerate() {
        put_hexbit(&mut x, j, h);
        j += if i == 15 { 4 } else { 3 };
    }
    x
}

/// A SACCH burst carrying a MAC PDU of `payload` (21 octets): RS(63,35) with CRC-12, the last 6
/// parity symbols not sent.
fn burst_sacch(payload: &[u8; 21]) -> [u8; 170] {
    let mut x = burst(BURST_SACCH_S);
    let bits: Vec<u8> = payload.iter().flat_map(|b| (0..8).rev().map(move |i| b >> i & 1)).collect();
    let crc = crc12(&bits, 168);
    let mut hb = [0u8; 63];
    for (j, c) in bits.chunks(6).enumerate() {
        hb[5 + j] = c.iter().fold(0, |v, &b| v << 1 | b);
    }
    hb[33] = (crc >> 6) as u8 & 63;
    hb[34] = crc as u8 & 63;
    rs_encode(&mut hb, 28);
    let sent: Vec<u8> = hb[5..57].iter().flat_map(|&h| (0..6).rev().map(move |i| h >> i & 1)).collect();
    let mut k = 0;
    for (start, n) in [(11usize, 36usize), (48, 84), (133, 36)] {
        for d in &mut x[start..start + n] {
            *d = sent[k] << 1 | sent[k + 1];
            k += 2;
        }
    }
    x
}

fn mac_ptt(mi: &[u8; 9], algid: u8, kid: u16, source: u32, group: u16, offset: u8) -> [u8; 21] {
    let mut b = [0u8; 21];
    b[0] = MAC_PTT << 5 | offset << 2;
    b[1..10].copy_from_slice(mi);
    b[10] = algid;
    b[11] = (kid >> 8) as u8;
    b[12] = kid as u8;
    b[13..16].copy_from_slice(&source.to_be_bytes()[1..]);
    b[16] = (group >> 8) as u8;
    b[17] = group as u8;
    b
}

/// A call on one logical channel of a Phase 2 voice channel.
#[derive(Clone, Debug)]
pub struct Call {
    pub nac: u32,
    pub sys_id: u32,
    pub wacn: u32,
    pub tgid: u16,
    pub source: u32,
    pub crypt: Option<Crypt>,
    /// Voice superframes of 360 ms.
    pub superframes: usize,
    /// The logical channel (0 or 1) that carries it.
    pub channel: usize,
    /// [`Start::Header`]: a MAC_PTT first. [`Start::Ldu1`]: none, and the stream starts as a voice
    /// superframe does (a receiver that joined then). [`Start::Ldu2`]: none, and the first
    /// superframe's first two 4V bursts are not sent either (a join part-way through it).
    pub start: Start,
}

impl Call {
    /// The channel's dibits, superframe after superframe: one idle, with the PTT on its SACCH (if
    /// the call has one), then the voice, then the end of the transmission. Voice frame `n` is `voice(n)`.
    pub fn dibits(&self, voice: impl Fn(usize) -> [u8; 49]) -> Result<Vec<u8>, CryptError> {
        let mask = xor_mask(self.nac, self.sys_id, self.wacn);
        let (algid, kid) = self.crypt.as_ref().map_or((ALGID_CLEAR, 0), |c| (c.algid, c.kid));
        let first_mi = self.crypt.as_ref().map_or([0u8; 9], |c| c.mi);
        let my_slots: Vec<usize> = (0..12).filter(|&s| SLOT_CHANNEL[s] == self.channel).collect();
        let sacch = *my_slots.last().unwrap();
        let idle = |slot: usize| slot_packet(slot, &burst_sacch(&[0; 21]), &mask);
        let mut out: Vec<u8> = Vec::new();
        // Before the voice: an idle superframe (the receiver settles), and the PTT at the end of it.
        let lead = if self.start == Start::Header { 2 } else { 1 };
        for sf in 0..lead {
            for slot in 0..12 {
                let ptt = self.start == Start::Header && sf == lead - 1 && slot == sacch;
                // The PTT's offset: slots from here to the first 4V burst of the voice that follows.
                let p = if ptt { slot_packet(slot, &burst_sacch(&mac_ptt(&first_mi, algid, kid, self.source, self.tgid, 4)), &mask) } else { idle(slot) };
                out.extend(p);
            }
        }
        let mut mi = first_mi;
        for s in 0..self.superframes {
            let stream = self.crypt.as_ref().map(|c| Keystream::new(c.algid, &c.key, &mi)).transpose()?;
            let next = if self.crypt.is_some() { next_mi(&mi) } else { [0; 9] };
            let (ess_b, ess_a) = ess(algid, kid, &next);
            let frame = |f: usize| -> [u8; 49] {
                let mut bits = voice(18 * s + f);
                if let Some(st) = &stream {
                    st.apply_tdma(f, &mut bits);
                }
                bits
            };
            #[allow(clippy::needless_range_loop)]
            for slot in 0..12 {
                let x = if SLOT_CHANNEL[slot] != self.channel || slot == sacch {
                    // (The other channel, and this one's SACCH slot while it carries no PDU: idle.)
                    burst_sacch(&[0; 21])
                } else {
                    let idx = my_slots.iter().position(|&m| m == slot).unwrap();
                    if idx < 4 {
                        burst_4v(&std::array::from_fn(|k| frame(4 * idx + k)), &ess_b, idx)
                    } else {
                        burst_2v(&std::array::from_fn(|k| frame(16 + k)), &ess_a)
                    }
                };
                // (A join part-way through the first superframe: its first four slots were missed.)
                if !(s == 0 && self.start == Start::Ldu2 && slot < 4) {
                    out.extend(slot_packet(slot, &x, &mask));
                }
            }
            mi = next;
        }
        // The end of the transmission, on the SACCH of one more superframe.
        #[allow(clippy::needless_range_loop)]
        for slot in 0..12 {
            let mut end = [0u8; 21];
            end[0] = MAC_END_PTT << 5;
            let p = if slot == sacch && SLOT_CHANNEL[slot] == self.channel { slot_packet(slot, &burst_sacch(&end), &mask) } else { idle(slot) };
            out.extend(p);
        }
        Ok(out)
    }
}

/// π/4-DQPSK-style H-DQPSK at 6000 baud (phase steps of ±π/4 and ±3π/4 for the dibits 00, 01,
/// 10, 11 as the receiver reads them), RRC-shaped (α 0.35), `fs` samples per second, `offset_hz` off centre.
pub fn modulate(dibits: &[u8], fs: f64, offset_hz: f64, amp: f32, phase: &mut f64) -> Vec<Complex32> {
    let sps = (fs / SYMBOL_RATE).round() as usize;
    assert!((fs / SYMBOL_RATE - sps as f64).abs() < 1e-9, "the sample rate must be a whole number of samples per symbol");
    let taps = filters::rrc_taps(0.35, sps as f64, 8 * sps + 1);
    let step = [std::f64::consts::FRAC_PI_4, 3.0 * std::f64::consts::FRAC_PI_4, -std::f64::consts::FRAC_PI_4, -3.0 * std::f64::consts::FRAC_PI_4];
    let mut x = vec![Complex32::default(); dibits.len() * sps + taps.len()];
    let mut ph = 0.0f64;
    for (k, &d) in dibits.iter().enumerate() {
        ph += step[(d & 3) as usize];
        let s = Complex32::from_polar(1.0, ph as f32);
        for (j, &t) in taps.iter().enumerate() {
            // (The taps have unit DC gain: a symbol every `sps` samples needs `sps` times that.)
            x[k * sps + j] += s * (t * sps as f32);
        }
    }
    // (The filter's delay is left in: a constant lead of half the filter.)
    x.iter()
        .map(|&v| {
            *phase += 2.0 * std::f64::consts::PI * offset_hz / fs;
            v * Complex32::from_polar(amp, *phase as f32)
        })
        .collect()
}
