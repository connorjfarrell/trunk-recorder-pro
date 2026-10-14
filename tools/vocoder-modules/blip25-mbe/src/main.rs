//! Trunk Recorder Pro vocoder module: the openBLIP25 `blip25-mbe` crate, IMBE
//! only. Its no-FEC IMBE frame carries no error counts, so a frame the FEC
//! counts condemn (or a lost one) is replaced by the crate's erasure marker,
//! which it conceals itself: repeat the last good frame, then comfort noise
//! after four in a row.

use blip25_mbe::vocoder::{FrameDisposition, Rate, Vocoder as Blip};
use vocoder_module_sdk::{Kind, Vocoder, FRAME_SAMPLES};

/// Repeat thresholds for the soft-decision FEC counts the recorder reports:
/// first-codeword errors and total errors (it repeats at E0 >= 4 or ET >= 16).
const REPEAT_E0: u8 = 4;
const REPEAT_ET: u8 = 16;

struct Module(Blip);

impl Module {
    fn new() -> Module {
        Module(Blip::new(Rate::Imbe4400x4400))
    }
}

impl Vocoder for Module {
    fn imbe(&mut self, bits: &[u8; 88], e0: u8, et: u8, erased: bool) -> (Kind, [i16; FRAME_SAMPLES]) {
        let mut bytes = [0u8; 11];
        if erased || e0 >= REPEAT_E0 || et >= REPEAT_ET {
            bytes.copy_from_slice(&self.0.rate().erasure_frame());
        } else {
            for (i, &b) in bits.iter().enumerate() {
                bytes[i / 8] |= (b & 1) << (7 - i % 8);
            }
        }
        let mut out = [0i16; FRAME_SAMPLES];
        match self.0.decode_bits(&bytes) {
            Ok(pcm) => out.iter_mut().zip(pcm).for_each(|(o, s)| *o = s),
            Err(_) => return (Kind::Muted, out),
        }
        let kind = match self.0.last_stats().decode.as_ref().map(|s| s.disposition) {
            Some(FrameDisposition::Repeat) => Kind::Repeat,
            Some(FrameDisposition::Mute | FrameDisposition::Silence) => Kind::Muted,
            _ => Kind::Voice,
        };
        (kind, out)
    }
}

fn main() {
    vocoder_module_sdk::serve(Module::new());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A voiced-speech-like signal: a 140 Hz buzz with a decaying harmonic series.
    fn tone(n: usize) -> Vec<i16> {
        (0..n)
            .map(|i| {
                let t = i as f64 / 8000.0;
                (1..=20).map(|h| 3000.0 / h as f64 * (2.0 * std::f64::consts::PI * 140.0 * h as f64 * t).sin()).sum::<f64>() as i16
            })
            .collect()
    }

    /// The module packs the recorder's bit array the way the crate's info-only
    /// IMBE frame is packed: decoding must equal the crate's own.
    #[test]
    fn bits_decode_like_the_crates_own_frames() {
        let mut enc = Blip::new(Rate::Imbe4400x4400);
        let mut direct = Blip::new(Rate::Imbe4400x4400);
        let mut module = Module::new();
        let mut loud = 0;
        for f in tone(160 * 60).chunks(160) {
            let bytes = enc.encode_pcm(f).unwrap();
            if bytes.is_empty() {
                continue;
            }
            let mut bits = [0u8; 88];
            for (i, b) in bits.iter_mut().enumerate() {
                *b = bytes[i / 8] >> (7 - i % 8) & 1;
            }
            let want = direct.decode_bits(&bytes).unwrap();
            let (_, got) = module.imbe(&bits, 0, 0, false);
            assert_eq!(&got[..], &want[..]);
            loud += got.iter().filter(|s| s.abs() > 500).count();
        }
        assert!(loud > 100, "the module is silent: {loud}");
    }

    #[test]
    fn a_condemned_frame_is_concealed() {
        let mut module = Module::new();
        let (kind, _) = module.imbe(&[0; 88], 0, 0, true);
        assert_ne!(kind, Kind::Voice);
        let (kind, _) = module.imbe(&[0; 88], 9, 30, false);
        assert_ne!(kind, Kind::Voice);
    }
}
