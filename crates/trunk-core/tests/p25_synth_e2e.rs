//! The whole path, from IQ to saved audio, for a P25 Phase 1 call that is encrypted: a synthetic
//! transmitter ([`trunk_core::p25::synth`]) sends the call (C4FM at 2.4 MS/s, in noise) to a real
//! engine with a conventional P25 channel, and the engine's saved call is compared with the same
//! call sent in the clear. What this shows is that the pieces work together: the receiver, framer,
//! tracker, keys, decryption, admission and saving. That the cipher is the standard's is shown
//! by the unit tests against its examples, and by real recordings.

use std::sync::Arc;

use num_complex::Complex32;
use trunk_core::crypto::{Key, KeyStore};
use trunk_core::p25::synth::{imbe, modulate, Call, Crypt, Start};
use trunk_core::trunk::sdr::sdr_frames;
use trunk_core::trunk::{CallConfig, ConvChannel, ConvMode, ConvSystem, Engine, EngineConfig, Event, SaveRules, SourceConfig, DEFAULT_GUARD_HZ};

const FS: f64 = 2_400_000.0;
const CENTER: f64 = 155_150_000.0;
const FREQ: f64 = 155_200_000.0;
const KEY: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
const MI: [u8; 9] = [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0];
const SUPERFRAMES: usize = 3;

fn call(crypt: Option<(u8, u16, &[u8])>, start: Start) -> Call {
    Call {
        nac: 0x293,
        tgid: 1001,
        source: 4_567_890,
        crypt: crypt.map(|(algid, kid, key)| Crypt { algid, kid, key: zeroize::Zeroizing::new(key.to_vec()), mi: MI }),
        superframes: SUPERFRAMES,
        start,
    }
}

fn keys(algid: u8, kid: u16, key: &[u8]) -> Arc<KeyStore> {
    let mut s = KeyStore::new();
    s.insert(Key::new(algid, kid, "test".into(), 0, true, key.to_vec()));
    Arc::new(s)
}

/// The air: half a second of noise, the call, a second and a half of noise.
fn air(c: &Call) -> Vec<Complex32> {
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    let mut noise = |n: usize| -> Vec<Complex32> {
        (0..n)
            .map(|_| {
                let mut u = || {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    ((seed >> 11) as f64 + 0.5) / (1u64 << 53) as f64
                };
                let (a, b) = (u(), u());
                let r = (-2.0 * a.ln()).sqrt() * 0.01;
                let t = 2.0 * std::f64::consts::PI * b;
                Complex32::new((r * t.cos()) as f32, (r * t.sin()) as f32)
            })
            .collect()
    };
    // 120 ms of alternating outer symbols first, as a radio's key-up: the receiver settles on it.
    let mut dibits: Vec<u8> = (0..576).map(|i| if i % 2 == 0 { 0b01 } else { 0b11 }).collect();
    dibits.extend(c.frames(imbe).unwrap().into_iter().flatten());
    let mut iq = noise((FS * 0.5) as usize);
    let mut phase = 0.0;
    let mut tx = modulate(&dibits, FS, FREQ - CENTER, 0.25, &mut phase);
    for (t, n) in tx.iter_mut().zip(noise(dibits.len() * 500)) {
        *t += n;
    }
    iq.extend(tx);
    iq.extend(noise((FS * 1.5) as usize));
    iq
}

/// What the engine saved of the call (None: it saved nothing), and what it said of the call.
struct Saved {
    audio: Vec<f32>,
    json: String,
    frames: Vec<Vec<u8>>,
}

fn run(iq: &[Complex32], keys: Option<Arc<KeyStore>>) -> Option<Saved> {
    let cfg = EngineConfig {
        sources: vec![SourceConfig { center_hz: CENTER, rate_hz: FS, auto_tune: false, guard_hz: DEFAULT_GUARD_HZ }],
        conventional: vec![ConvChannel::new(FREQ, ConvMode::P25)],
        conv_systems: vec![ConvSystem { short_name: "conv".into(), calls: CallConfig { call_timeout_s: 1.0, ..Default::default() }, save: SaveRules { normalize: false, ..Default::default() }, ..Default::default() }],
        capture_frames: true,
        keys,
        ..Default::default()
    };
    let mut e = Engine::new(cfg).unwrap();
    let mut saved = None;
    for chunk in iq.chunks(32768) {
        e.push_iq(0, chunk);
        for ev in e.drain_events() {
            if let Event::Concluded(k) = ev {
                let frames = k.frames.as_ref().map(|c| sdr_frames(&c.bytes).into_iter().map(|f| f.bits).collect()).unwrap_or_default();
                assert!(saved.is_none(), "one call");
                saved = Some(Saved { audio: k.audio, json: k.json, frames });
            }
        }
    }
    saved
}

fn clear_bits(range: std::ops::Range<usize>) -> Vec<Vec<u8>> {
    range.map(|n| imbe(n).to_vec()).collect()
}

/// Which frames differ (their numbers), instead of printing them all.
fn differing(got: &[Vec<u8>], want: &[Vec<u8>]) -> String {
    let bad: Vec<usize> = (0..got.len().max(want.len())).filter(|&i| got.get(i) != want.get(i)).collect();
    format!("{} frames got, {} wanted; differing: {bad:?}", got.len(), want.len())
}

#[test]
fn an_encrypted_call_is_saved_decrypted_as_the_clear_call_is() {
    let clear = run(&air(&call(None, Start::Header)), None).expect("the clear call is saved");
    assert!(clear.frames == clear_bits(0..18 * SUPERFRAMES), "the clear call's frames come through as sent: {}", differing(&clear.frames, &clear_bits(0..18 * SUPERFRAMES)));
    assert!(clear.audio.len() >= 18 * SUPERFRAMES * 160 && clear.audio.iter().any(|&s| s.abs() > 0.01));

    // DES-OFB, AES-256 and ADP, each with its key.
    let aes = [0x5au8; 32];
    let adp = [0xde, 0xad, 0xbe, 0xef, 0x69];
    for (algid, kid, key) in [(0x81u8, 7u16, &KEY[..]), (0x84, 1235, &aes[..]), (0xaa, 1234, &adp[..])] {
        let iq = air(&call(Some((algid, kid, key)), Start::Header));
        let got = run(&iq, Some(keys(algid, kid, key))).unwrap_or_else(|| panic!("{algid:#04x}: the decrypted call is saved"));
        assert!(got.frames == clear.frames, "{algid:#04x}: the frames are the clear call's: {}", differing(&got.frames, &clear.frames));
        assert_eq!(got.audio, clear.audio, "{algid:#04x}: so is the audio");
        assert!(got.json.contains(&format!("\"encrypted\":1,\"decrypted\":1,\"alg_id\":{algid},\"key_id\":{kid},")), "{}", got.json);
        assert!(!got.json.contains("deadbeef"), "no key in the JSON");
    }
}

#[test]
fn without_the_key_nothing_of_the_voice_is_saved() {
    let iq = air(&call(Some((0x81, 7, &KEY)), Start::Header));
    // No keys at all: as before there were any.
    assert!(run(&iq, None).is_none(), "an encrypted call with no keys loaded has no audio to save");
    // Keys, but not for this key id, or for another cipher.
    assert!(run(&iq, Some(keys(0x81, 8, &KEY))).is_none(), "another key id");
    assert!(run(&iq, Some(keys(0x84, 7, &[1; 32]))).is_none(), "another algorithm");
}

#[test]
fn the_wrong_key_gives_noise_not_the_call() {
    let iq = air(&call(Some((0x81, 7, &KEY)), Start::Header));
    let got = run(&iq, Some(keys(0x81, 7, &[0x11; 8]))).expect("a key is a key: the call is saved");
    assert!(got.frames != clear_bits(0..18 * SUPERFRAMES));
}

#[test]
fn a_call_joined_late_is_decrypted_from_where_it_is_joined() {
    // Joined at an LDU1: the MI is learned from the LDU2 after it, and the held frames come out too.
    let got = run(&air(&call(Some((0x81, 7, &KEY)), Start::Ldu1)), Some(keys(0x81, 7, &KEY))).expect("saved");
    let want = clear_bits(0..18 * SUPERFRAMES);
    assert!(got.frames == want, "nothing of the first LDU1 is lost: {}", differing(&got.frames, &want));
    // Joined at an LDU2: the first LDU1 was never sent.
    let got = run(&air(&call(Some((0x81, 7, &KEY)), Start::Ldu2)), Some(keys(0x81, 7, &KEY))).expect("saved");
    let want = clear_bits(9..18 * SUPERFRAMES);
    assert!(got.frames == want, "{}", differing(&got.frames, &want));
}
