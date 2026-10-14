//! The two openBLIP25 IMBE decoders, for P25 Phase 1: `blip25-mbe` and
//! `blip25-vocoder`. Both are MIT-licensed pure Rust, with their optional
//! post-filter left off.
//!
//! Provenance matters: the wire framing and FEC are spec-derived, but each
//! project's PATENT_NOTICE.md says its analysis/synthesis core (IMBE as much as
//! AMBE+2) was reverse-engineered from a compiled reference vocoder, is
//! patent-encumbered, and is for research and interoperability study. Anyone
//! building or distributing with these profiles takes that on themselves.
//!
//! Neither gets the soft-decision repeat thresholds or the enhanced concealment
//! of [`super::Profile::Enhanced`]: each does its own, from the same FEC counts.
//! AMBE+2 never goes through them (it stays on the enhanced decoder).

use super::{Kind, FRAME_SAMPLES};

/// Widths of u0..u7 in the 88 information bits.
const WIDTHS: [usize; 8] = [12, 12, 12, 12, 11, 11, 11, 7];

/// Output scale: [`super::to_limited`] / [`super::to_unit`] multiply mbelib's
/// float scale by 7, so hand them i16 / 7.
const SCALE: f32 = 1.0 / 7.0;

pub(super) enum Blip25 {
    /// blip25-mbe: the no-FEC IMBE frame carries no error counts, so a frame
    /// the FEC thresholds reject is replaced by its erasure marker, which the
    /// codec conceals itself (repeat, then comfort noise after four).
    Mbe(blip25_mbe::vocoder::Vocoder),
    /// blip25-vocoder: takes the info vectors and a [`FrameStatus`] whose
    /// severity drives its concealment.
    ///
    /// [`FrameStatus`]: blip25_vocoder::vocoder::FrameStatus
    Vocoder(blip25_vocoder::vocoder::Vocoder),
}

impl Blip25 {
    pub(super) fn mbe() -> Self {
        Blip25::Mbe(blip25_mbe::vocoder::Vocoder::new(blip25_mbe::vocoder::Rate::Imbe4400x4400))
    }

    pub(super) fn vocoder() -> Self {
        Blip25::Vocoder(blip25_vocoder::vocoder::Vocoder::new(blip25_vocoder::vocoder::Rate::FullRate4400x4400))
    }

    pub(super) fn reset(&mut self) {
        match self {
            Blip25::Mbe(v) => v.reset(),
            Blip25::Vocoder(v) => v.reset(),
        }
    }

    /// One frame. `bad`: the caller's repeat rule fired (only blip25-mbe uses
    /// it; blip25-vocoder judges from `et`).
    pub(super) fn imbe(&mut self, d: &[u8; 88], et: u32, erased: bool, bad: bool, out: &mut [f32; FRAME_SAMPLES]) -> Kind {
        match self {
            Blip25::Mbe(v) => {
                let mut bytes = [0u8; 11];
                if bad {
                    bytes.copy_from_slice(&v.rate().erasure_frame());
                } else {
                    for (i, &b) in d.iter().enumerate() {
                        bytes[i / 8] |= (b & 1) << (7 - i % 8);
                    }
                }
                let pcm = v.decode_bits(&bytes).unwrap_or_else(|_| vec![0; FRAME_SAMPLES]);
                fill(out, &pcm);
                use blip25_mbe::vocoder::FrameDisposition as D;
                match v.last_stats().decode.as_ref().map(|s| s.disposition) {
                    Some(D::Repeat) => Kind::Repeat,
                    Some(D::Mute) | Some(D::Silence) => Kind::Muted,
                    _ => Kind::Voice,
                }
            }
            Blip25::Vocoder(v) => {
                use blip25_vocoder::vocoder::FrameStatus;
                let mut info = [0u16; 8];
                let mut p = 0;
                for (u, &w) in info.iter_mut().zip(WIDTHS.iter()) {
                    *u = d[p..p + w].iter().fold(0, |v, &b| v << 1 | (b & 1) as u16);
                    p += w;
                }
                let status = if erased { FrameStatus::LOST } else { FrameStatus::new(et, false) };
                let pcm = v.decode_info(&info, status).unwrap_or_else(|_| vec![0; FRAME_SAMPLES]);
                fill(out, &pcm);
                match v.last_stats().decode.as_ref().map(|s| s.disposition) {
                    Some(f) if f.is_tone() => Kind::Tone,
                    Some(f) if f.is_concealed() => Kind::Repeat,
                    _ => Kind::Voice,
                }
            }
        }
    }
}

fn fill(out: &mut [f32; FRAME_SAMPLES], pcm: &[i16]) {
    for (o, &v) in out.iter_mut().zip(pcm) {
        *o = v as f32 * SCALE;
    }
}
