//! The vocoder module protocol (docs/developer/vocoder-modules.md) for a
//! module written in Rust: implement [`Vocoder`] and call [`serve`].
//!
//! ```no_run
//! use vocoder_module_sdk::{serve, Kind, Vocoder, FRAME_SAMPLES};
//!
//! struct Silence;
//!
//! impl Vocoder for Silence {
//!     fn imbe(&mut self, _bits: &[u8; 88], _e0: u8, _et: u8, _erased: bool) -> (Kind, [i16; FRAME_SAMPLES]) {
//!         (Kind::Voice, [0; FRAME_SAMPLES])
//!     }
//! }
//!
//! fn main() {
//!     serve(Silence);
//! }
//! ```

use std::io::{self, Read, Write};

pub const FRAME_SAMPLES: usize = 160;

/// What the frame turned out to be; the recorder counts repeated and muted
/// frames as a call's bad frames.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Kind {
    Voice = 0,
    /// The previous frame's audio, held because this one was unusable.
    Repeat = 1,
    Muted = 2,
    Erasure = 3,
    Tone = 4,
}

/// One decoding stream. The recorder starts one process per stream (a call, or
/// one timeslot of one), so state lives in `self` and frames arrive in order.
pub trait Vocoder {
    /// A new call begins.
    fn reset(&mut self) {}

    /// One IMBE 7200x4400 (P25 Phase 1) frame: its 88 information bits, one per
    /// byte (0 or 1, mbelib's imbe_d order), the FEC errors found in the first
    /// codeword and in all of them, and whether the frame was lost outright.
    /// Return 160 samples (8 kHz, 16-bit, full scale 32767).
    fn imbe(&mut self, bits: &[u8; 88], e0: u8, et: u8, erased: bool) -> (Kind, [i16; FRAME_SAMPLES]);

    /// One AMBE+2 3600x2450 (P25 Phase 2, DMR, NXDN) frame: 49 information bits
    /// (mbelib's ambe_d) and the FEC errors found. Only called if the module's
    /// `module.json` lists "ambe".
    fn ambe(&mut self, _bits: &[u8; 49], _errs: u8) -> (Kind, [i16; FRAME_SAMPLES]) {
        (Kind::Muted, [0; FRAME_SAMPLES])
    }
}

const OP_IMBE: u8 = 1;
const OP_AMBE: u8 = 2;
const OP_RESET: u8 = 3;

/// Say the module couldn't start (no dongle, bad setting) and exit. Call it
/// instead of [`serve`].
pub fn fail(message: &str) -> ! {
    let line = format!("{{\"type\":\"error\",\"message\":{}}}", json_string(message));
    println!("{line}");
    std::process::exit(1);
}

fn json_string(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            c if (c as u32) < 0x20 => o.push(' '),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

/// Serve the recorder on stdin and stdout until it closes stdin.
pub fn serve<V: Vocoder>(vocoder: V) {
    let (stdin, stdout) = (io::stdin(), io::stdout());
    if let Err(e) = serve_io(stdin.lock(), stdout.lock(), vocoder) {
        eprintln!("vocoder module: {e}");
        std::process::exit(1);
    }
}

/// [`serve`] on any reader and writer.
pub fn serve_io<R: Read, W: Write, V: Vocoder>(mut input: R, mut output: W, mut vocoder: V) -> io::Result<()> {
    output.write_all(b"{\"type\":\"ready\"}\n")?;
    output.flush()?;
    loop {
        let mut head = [0u8; 4];
        match input.read_exact(&mut head) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let [op, flags, e0, et] = head;
        let (kind, pcm) = match op {
            OP_IMBE => {
                let mut bits = [0u8; 88];
                input.read_exact(&mut bits)?;
                vocoder.imbe(&bits, e0, et, flags & 1 != 0)
            }
            OP_AMBE => {
                let mut bits = [0u8; 49];
                input.read_exact(&mut bits)?;
                vocoder.ambe(&bits, et)
            }
            OP_RESET => {
                vocoder.reset();
                (Kind::Voice, [0; FRAME_SAMPLES])
            }
            other => return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unknown request {other}"))),
        };
        let mut reply = [0u8; 1 + FRAME_SAMPLES * 2];
        reply[0] = kind as u8;
        for (b, s) in reply[1..].chunks_exact_mut(2).zip(pcm) {
            b.copy_from_slice(&s.to_le_bytes());
        }
        output.write_all(&reply)?;
        output.flush()?;
    }
}

/// Pack the 88 IMBE information bits into u0..u7 (12, 12, 12, 12, 11, 11, 11, 7 bits).
pub fn imbe_info(bits: &[u8; 88]) -> [u16; 8] {
    const W: [usize; 8] = [12, 12, 12, 12, 11, 11, 11, 7];
    let mut u = [0u16; 8];
    let mut p = 0;
    for (v, w) in u.iter_mut().zip(W) {
        *v = bits[p..p + w].iter().fold(0, |a, &b| a << 1 | (b & 1) as u16);
        p += w;
    }
    u
}

/// Pack the 49 AMBE+2 information bits into u0..u3 (12, 12, 11, 14 bits).
pub fn ambe_info(bits: &[u8; 49]) -> [u16; 4] {
    const W: [usize; 4] = [12, 12, 11, 14];
    let mut u = [0u16; 4];
    let mut p = 0;
    for (v, w) in u.iter_mut().zip(W) {
        *v = bits[p..p + w].iter().fold(0, |a, &b| a << 1 | (b & 1) as u16);
        p += w;
    }
    u
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Ramp(u32);

    impl Vocoder for Ramp {
        fn reset(&mut self) {
            self.0 = 0;
        }

        fn imbe(&mut self, bits: &[u8; 88], e0: u8, et: u8, erased: bool) -> (Kind, [i16; FRAME_SAMPLES]) {
            self.0 += 1;
            let mut pcm = [0i16; FRAME_SAMPLES];
            pcm[0] = self.0 as i16;
            pcm[1] = bits[0] as i16 + 10 * e0 as i16 + 100 * et as i16;
            (if erased { Kind::Repeat } else { Kind::Voice }, pcm)
        }
    }

    #[test]
    fn serves_frames_resets_and_exits_on_eof() {
        let mut input = Vec::new();
        input.extend_from_slice(&[OP_IMBE, 0, 2, 3]);
        input.extend_from_slice(&[1; 88]);
        input.extend_from_slice(&[OP_IMBE, 1, 0, 0]);
        input.extend_from_slice(&[0; 88]);
        input.extend_from_slice(&[OP_RESET, 0, 0, 0]);
        input.extend_from_slice(&[OP_IMBE, 0, 0, 0]);
        input.extend_from_slice(&[0; 88]);
        let mut out = Vec::new();
        serve_io(&input[..], &mut out, Ramp(0)).unwrap();
        let ready = b"{\"type\":\"ready\"}\n";
        assert!(out.starts_with(ready));
        let replies: Vec<&[u8]> = out[ready.len()..].chunks(1 + FRAME_SAMPLES * 2).collect();
        assert_eq!(replies.len(), 4);
        let sample = |r: &[u8], i: usize| i16::from_le_bytes([r[1 + 2 * i], r[2 + 2 * i]]);
        assert_eq!((replies[0][0], sample(replies[0], 0), sample(replies[0], 1)), (0, 1, 1 + 20 + 300));
        assert_eq!((replies[1][0], sample(replies[1], 0)), (1, 2));
        assert_eq!(replies[2][0], 0);
        assert_eq!(sample(replies[3], 0), 1, "the reset started the count over");
    }

    #[test]
    fn info_vectors_match_the_field_widths() {
        let mut bits = [0u8; 88];
        bits[11] = 1;
        bits[12 + 11] = 1;
        bits[87] = 1;
        assert_eq!(imbe_info(&bits), [1, 1, 0, 0, 0, 0, 0, 1]);
        let mut a = [0u8; 49];
        a[48] = 1;
        assert_eq!(ambe_info(&a), [0, 0, 0, 1]);
    }
}
