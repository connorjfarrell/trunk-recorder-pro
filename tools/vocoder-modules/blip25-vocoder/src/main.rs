//! Trunk Recorder Pro vocoder module: the openBLIP25 `blip25-vocoder` crate.
//! IMBE and AMBE+2 take their information vectors and a [`FrameStatus`] built
//! from the FEC error count, which drives the crate's own concealment.

use blip25_vocoder::vocoder::{FrameStatus, Rate, Vocoder as Blip};
use vocoder_module_sdk::{ambe_info, imbe_info, serve, Kind, Vocoder, FRAME_SAMPLES};

struct Module {
    imbe: Blip,
    ambe: Blip,
}

impl Module {
    fn new() -> Module {
        Module { imbe: Blip::new(Rate::FullRate4400x4400), ambe: Blip::new(Rate::HalfRate2450x2450) }
    }
}

fn frame(v: &mut Blip, info: &[u16], status: FrameStatus) -> (Kind, [i16; FRAME_SAMPLES]) {
    let mut out = [0i16; FRAME_SAMPLES];
    match v.decode_info(info, status) {
        Ok(pcm) => out.iter_mut().zip(pcm).for_each(|(o, s)| *o = s),
        Err(_) => return (Kind::Muted, out),
    }
    let kind = match v.last_stats().decode.as_ref().map(|s| s.disposition) {
        Some(d) if d.is_tone() => Kind::Tone,
        Some(d) if d.is_concealed() => Kind::Repeat,
        _ => Kind::Voice,
    };
    (kind, out)
}

impl Vocoder for Module {
    fn imbe(&mut self, bits: &[u8; 88], _e0: u8, et: u8, erased: bool) -> (Kind, [i16; FRAME_SAMPLES]) {
        let status = if erased { FrameStatus::LOST } else { FrameStatus::new(et as u32, false) };
        frame(&mut self.imbe, &imbe_info(bits), status)
    }

    fn ambe(&mut self, bits: &[u8; 49], errs: u8) -> (Kind, [i16; FRAME_SAMPLES]) {
        frame(&mut self.ambe, &ambe_info(bits), FrameStatus::new(errs as u32, false))
    }
}

fn main() {
    serve(Module::new());
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A voiced-ish test tone.
    fn tone(n: usize) -> Vec<i16> {
        (0..n).map(|i| (6000.0 * (i as f64 * 0.19).sin() + 2500.0 * (i as f64 * 0.57).sin()) as i16).collect()
    }

    /// Encode with the crate, unpack the info vectors into the bit arrays the
    /// recorder sends, and check the module decodes them exactly as the crate
    /// does from the vectors: the bit packing round-trips.
    #[test]
    fn imbe_bits_decode_like_the_info_vectors() {
        let mut enc = Blip::new(Rate::FullRate4400x4400);
        let mut direct = Blip::new(Rate::FullRate4400x4400);
        let mut module = Module::new();
        let pcm = tone(160 * 30);
        let mut loud = 0;
        for f in pcm.chunks(160) {
            let info = enc.encode_info(f).unwrap();
            let mut bits = [0u8; 88];
            let mut p = 0;
            for (v, w) in info.iter().zip([12, 12, 12, 12, 11, 11, 11, 7]) {
                for b in (0..w).rev() {
                    bits[p] = (v >> b & 1) as u8;
                    p += 1;
                }
            }
            let want = direct.decode_info(&info, FrameStatus::CLEAN).unwrap();
            let (_, got) = module.imbe(&bits, 0, 0, false);
            assert_eq!(&got[..], &want[..]);
            loud += got.iter().filter(|s| s.abs() > 500).count();
        }
        assert!(loud > 100, "the module is silent");
    }

    #[test]
    fn ambe_bits_decode_like_the_info_vectors() {
        let mut enc = Blip::new(Rate::HalfRate2450x2450);
        let mut direct = Blip::new(Rate::HalfRate2450x2450);
        let mut module = Module::new();
        let pcm = tone(160 * 30);
        let mut loud = 0;
        for f in pcm.chunks(160) {
            let info = enc.encode_info(f).unwrap();
            let mut bits = [0u8; 49];
            let mut p = 0;
            for (v, w) in info.iter().zip([12, 12, 11, 14]) {
                for b in (0..w).rev() {
                    bits[p] = (v >> b & 1) as u8;
                    p += 1;
                }
            }
            let want = direct.decode_info(&info, FrameStatus::CLEAN).unwrap();
            let (_, got) = module.ambe(&bits, 0);
            assert_eq!(&got[..], &want[..]);
            loud += got.iter().filter(|s| s.abs() > 500).count();
        }
        assert!(loud > 100, "the module is silent");
    }

    #[test]
    fn a_lost_frame_is_concealed() {
        let mut module = Module::new();
        let (kind, _) = module.imbe(&[0; 88], 0, 0, true);
        assert_ne!(kind, Kind::Voice);
    }
}
