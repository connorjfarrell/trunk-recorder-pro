//! Decrypt real-radio captures with their known keys: the P25 Phase 1
//! samples of <https://github.com/tylerwatt12/known-key-mbe-samples> (an
//! APX1000 for ADP, an XG-100P for DES-OFB and AES-256), which are not
//! licensed for redistribution and so are not in this repository.
//!
//! `KNOWN_KEY_SAMPLES=/path/to/known-key-mbe-samples cargo test --release \
//!   -p trunk-core --test known_key_samples -- --ignored --nocapture`
//!
//! For each sample: the MI chain must follow the LFSR from superframe to
//! superframe, and with the key the frames must vocode as speech (and as
//! loud and quiet as the sample's expected audio does) where with a wrong
//! key they do not.

use std::path::{Path, PathBuf};

use trunk_core::crypto::p25::{self, Keystream};
use trunk_core::mbe::{self, Kind, FRAME_SAMPLES};
use trunk_core::tables::VOICE_CODEWORD_BITS;
use trunk_core::p25::voice::{imbe_header_decode, imbe_params_to_bits};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap()).collect()
}

struct Sample {
    algid: u8,
    key: zeroize::Zeroizing<Vec<u8>>,
    /// Per frame: the 144 coded bits, and the MI marker it carries, if any.
    frames: Vec<([u8; 144], Option<p25::Mi>)>,
    expected: Vec<i16>,
}

fn load(dir: &Path) -> Sample {
    // (The file holds the key as text: kept wiped like the key, and only borrowed from.)
    let kv = zeroize::Zeroizing::new(std::fs::read_to_string(dir.join("key.txt")).unwrap());
    let get = |k: &str| -> &str { kv.lines().find_map(|l| l.strip_prefix(&format!("{k}="))).unwrap().trim() };
    let algid = u8::from_str_radix(get("algid").trim_start_matches("0x"), 16).unwrap();
    let key = zeroize::Zeroizing::new(unhex(get("key_hex")));
    let j: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(dir.join("encrypted.mbe")).unwrap()).unwrap();
    let frames = j["frames"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            let b = unhex(f["hex"].as_str().unwrap());
            // The sample holds the frame's 144 bits as sent, interleaved: the
            // codeword's bit j sits where VOICE_CODEWORD_BITS puts it in the
            // frame, so the order sent is the order of those positions.
            let mut order: Vec<usize> = (0..144).collect();
            order.sort_by_key(|&j| VOICE_CODEWORD_BITS[j]);
            let mut cw = [0u8; 144];
            for (i, &j) in order.iter().enumerate() {
                cw[j] = (b[i / 8] >> (7 - i % 8)) & 1;
            }
            let mi = f["encryption_mi"].as_str().map(|m| {
                let mut mi = [0u8; 9];
                mi.copy_from_slice(&unhex(m));
                mi
            });
            (cw, mi)
        })
        .collect();
    let wav = std::fs::read(dir.join("expected.wav")).unwrap();
    let expected = wav[44..].chunks(2).filter(|c| c.len() == 2).map(|c| i16::from_le_bytes([c[0], c[1]])).collect();
    Sample { algid, key, frames, expected }
}

fn rms(x: &[f32]) -> f32 {
    (x.iter().map(|v| v * v).sum::<f32>() / x.len().max(1) as f32).sqrt()
}

fn correlation(a: &[f32], b: &[f32]) -> f32 {
    let n = a.len().min(b.len());
    let (ma, mb) = (a[..n].iter().sum::<f32>() / n as f32, b[..n].iter().sum::<f32>() / n as f32);
    let (mut ab, mut aa, mut bb) = (0.0, 0.0, 0.0);
    for i in 0..n {
        let (x, y) = (a[i] - ma, b[i] - mb);
        ab += x * y;
        aa += x * x;
        bb += y * y;
    }
    ab / (aa * bb).sqrt().max(1e-9)
}

/// Vocode the frames with `key` (or, with None, as they are); (voice frames,
/// all frames, mean FEC errors, the RMS of each frame's audio).
fn vocode(s: &Sample, key: Option<&[u8]>, mi_chain: &[p25::Mi]) -> (usize, usize, f64, Vec<f32>) {
    let mut dec = mbe::Decoder::new(mbe::lcg(1), mbe::Profile::Enhanced);
    let (mut voice, mut errs, mut env) = (0, 0u64, Vec::new());
    let streams: Vec<Option<Keystream>> = mi_chain.iter().map(|mi| key.map(|k| Keystream::new(s.algid, k, mi).unwrap())).collect();
    for (i, (cw, _)) in s.frames.iter().enumerate() {
        let p = imbe_header_decode(cw, None);
        errs += p.errs as u64;
        let mut bits = imbe_params_to_bits(&p.u);
        let (sf, f) = (i / 18, i % 18);
        if let Some(ks) = &streams[sf] {
            ks.apply(f >= 9, f % 9, &mut bits);
        }
        let mut buf = [0f32; FRAME_SAMPLES];
        if dec.imbe(&bits, p.e0, p.errs, false, &mut buf) == Kind::Voice {
            voice += 1;
        }
        env.push(rms(&buf));
    }
    (voice, s.frames.len(), errs as f64 / s.frames.len() as f64, env)
}

#[test]
#[ignore = "needs KNOWN_KEY_SAMPLES (the known-key-mbe-samples repository)"]
fn p25_phase1_samples_decrypt_with_their_keys() {
    let root = PathBuf::from(std::env::var("KNOWN_KEY_SAMPLES").expect("KNOWN_KEY_SAMPLES"));
    let mut dirs: Vec<_> = std::fs::read_dir(&root).unwrap().map(|e| e.unwrap().path()).filter(|p| p.file_name().unwrap().to_string_lossy().starts_with("p25_")).collect();
    dirs.sort();
    assert!(!dirs.is_empty(), "no p25_* samples in {root:?}");
    for dir in dirs {
        let s = load(&dir);
        // The MI of each superframe: the marker on its first frame, or the chain's next.
        let sfs = s.frames.len().div_ceil(18);
        let mut chain: Vec<p25::Mi> = Vec::new();
        let mut markers_ok = 0;
        for sf in 0..sfs {
            let marked = s.frames.get(sf * 18).and_then(|f| f.1);
            let from_chain = chain.last().map(p25::next_mi);
            if let (Some(m), Some(c)) = (marked, from_chain) {
                markers_ok += (m[..8] == c[..8]) as usize;
            }
            chain.push(marked.or(from_chain).expect("a first MI"));
        }
        let (voice, n, errs, good) = vocode(&s, Some(&s.key), &chain);
        let mut wrong = zeroize::Zeroizing::new(s.key.to_vec());
        wrong[0] ^= 0x55;
        let (wvoice, _, _, wenv) = vocode(&s, Some(&wrong), &chain);
        let (cvoice, _, _, _) = vocode(&s, None, &chain);
        // The envelope of the audio against the sample's expected audio.
        let expected: Vec<f32> = s.expected.chunks(FRAME_SAMPLES).map(|c| rms(&c.iter().map(|&v| v as f32).collect::<Vec<_>>())).collect();
        let corr = correlation(&good, &expected);
        let wcorr = correlation(&wenv, &expected);
        println!(
            "{:<18} alg {:#04x}: {} superframes, MI chain {}/{} marked ok; mean FEC errs {:.2}; voice frames {}/{} with the key, {} with a wrong key, {} undecrypted; envelope correlation {:.3} (wrong key {:.3})",
            dir.file_name().unwrap().to_string_lossy(),
            s.algid,
            sfs,
            markers_ok,
            sfs - 1,
            errs,
            voice,
            n,
            wvoice,
            cvoice,
            corr,
            wcorr
        );
        let name = dir.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(markers_ok, sfs - 1, "{name}: each superframe's MI is the LFSR's step from the last");
        assert!(errs < 0.5, "{name}: the frames are read with few FEC errors");
        assert!(voice * 100 >= n * 99, "{name}: the decrypted frames vocode as voice");
        assert!(corr > 0.85 && wcorr < 0.5, "{name}: the audio follows the expected audio with the key ({corr}) and not without ({wcorr})");
    }
}
