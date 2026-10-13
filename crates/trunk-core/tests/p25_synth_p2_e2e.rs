//! Phase 2 from IQ to AMBE frames: a synthetic transmitter ([`trunk_core::p25::synth_p2`]) sends a
//! call as H-DQPSK, and the real Phase 2 voice decoder (receiver, slot framer, tracker) with the
//! system's scrambler seed and the keys gives the frames of the clear call back. Phase 1's twin is
//! `p25_synth_e2e.rs`; there the engine's saving is in the path too, here (a trunked call needs a
//! control channel) the decoder's output is compared. The cipher and its Phase 2 layout are checked
//! against the standard's examples in the unit tests; this shows the rest works together.

use std::sync::Arc;

use num_complex::Complex32;
use trunk_core::crypto::{Key, KeyStore};
use trunk_core::nxdn::synth::ambe;
use trunk_core::p25::diversity::BankConfig;
use trunk_core::p25::synth::{Crypt, Start};
use trunk_core::p25::synth_p2::{modulate, Call};
use trunk_core::trunk::voice::{self, TrackerOut, VoiceKind, VoiceParams, VoiceSpec};

const FS: f64 = 48_000.0;
const MI: [u8; 9] = [0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0];
const SUPERFRAMES: usize = 3;
const SYSTEM: (u32, u32, u32) = (0x293, 0x2a5, 0xbee00);

fn call(crypt: Option<(u8, u16, &[u8])>, start: Start, channel: usize) -> Call {
    Call {
        nac: SYSTEM.0,
        sys_id: SYSTEM.1,
        wacn: SYSTEM.2,
        tgid: 1001,
        source: 4_567_890,
        crypt: crypt.map(|(algid, kid, key)| Crypt { algid, kid, key: key.to_vec(), mi: MI }),
        superframes: SUPERFRAMES,
        channel,
        start,
    }
}

fn keys(algid: u8, kid: u16, key: &[u8]) -> Arc<KeyStore> {
    let mut s = KeyStore::new();
    s.insert(Key::new(algid, kid, "test".into(), 0, true, key.to_vec()));
    Arc::new(s)
}

fn air(c: &Call) -> Vec<Complex32> {
    let dibits = c.dibits(ambe).unwrap();
    let mut phase = 0.0;
    let mut iq = modulate(&dibits, FS, 0.0, 0.5, &mut phase);
    // A little noise, and silence after.
    let mut seed = 0x2545_f491_4f6c_dd1du64;
    for v in iq.iter_mut() {
        let mut u = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            ((seed >> 11) as f64 + 0.5) / (1u64 << 53) as f64
        };
        let (a, b) = (u(), u());
        let r = (-2.0 * a.ln()).sqrt() * 0.005;
        let t = 2.0 * std::f64::consts::PI * b;
        *v += Complex32::new((r * t.cos()) as f32, (r * t.sin()) as f32);
    }
    iq.extend(std::iter::repeat_n(Complex32::default(), 24_000));
    iq
}

/// The AMBE frames (49 bits) the decoder made of logical channel `channel`, and what it told the call.
/// (Frames, then what it told the call: (algorithm, key id, decrypted).)
type Heard = (Vec<Vec<u8>>, Vec<(u8, u16, bool)>);

fn decode(iq: &[Complex32], channel: usize, keys: Option<Arc<KeyStore>>) -> Heard {
    let spec = VoiceSpec { kind: VoiceKind::Tdma, rate: FS, t0: 0.0, seed: 1, vocoder: trunk_core::mbe::Profile::Enhanced, bank: BankConfig::default(), squelch: 0.0, subaudible: false };
    let mut d = voice::build(&spec);
    d.set_params(&VoiceParams { tdma_key: Some(SYSTEM) });
    if let Some(k) = keys {
        d.set_keys(k);
    }
    let (mut frames, mut said) = (Vec::new(), Vec::new());
    let mut out = Vec::new();
    for chunk in iq.chunks(4800) {
        d.push(chunk, &mut out);
        for o in out.drain(..).filter(|o| o.slot as usize == channel) {
            match o.out {
                TrackerOut::Audio(_, f) => frames.push(f.bits),
                TrackerOut::Crypto { algid, key_id, decrypted } => said.push((algid, key_id, decrypted)),
                _ => {}
            }
        }
    }
    (frames, said)
}

fn clear_frames(range: std::ops::Range<usize>) -> Vec<Vec<u8>> {
    range.map(|n| ambe(n).to_vec()).collect()
}

fn differing(got: &[Vec<u8>], want: &[Vec<u8>]) -> String {
    let bad: Vec<usize> = (0..got.len().max(want.len())).filter(|&i| got.get(i) != want.get(i)).collect();
    format!("{} frames got, {} wanted; differing: {bad:?}", got.len(), want.len())
}

#[test]
fn a_clear_phase_2_call_comes_through_on_either_channel() {
    for channel in [0, 1] {
        let (frames, said) = decode(&air(&call(None, Start::Header, channel)), channel, None);
        let want = clear_frames(0..18 * SUPERFRAMES);
        assert!(frames == want, "channel {channel}: {}", differing(&frames, &want));
        assert!(said.is_empty(), "no keys, nothing said");
    }
}

#[test]
fn an_encrypted_phase_2_call_is_decrypted_with_its_key() {
    let aes = [0x5au8; 32];
    let adp = [0xde, 0xad, 0xbe, 0xef, 0x69];
    let des = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    for (algid, kid, key) in [(0x81u8, 7u16, &des[..]), (0x84, 1235, &aes[..]), (0xaa, 1234, &adp[..])] {
        let iq = air(&call(Some((algid, kid, key)), Start::Header, 0));
        let (frames, said) = decode(&iq, 0, Some(keys(algid, kid, key)));
        let want = clear_frames(0..18 * SUPERFRAMES);
        assert!(frames == want, "{algid:#04x}: {}", differing(&frames, &want));
        assert_eq!(said, [(algid, kid, true)], "{algid:#04x}: said once that it decrypts");
    }
}

#[test]
fn without_the_key_nothing_is_decoded_and_the_wrong_key_gives_noise() {
    let des = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let iq = air(&call(Some((0x81, 7, &des)), Start::Header, 0));
    let (frames, said) = decode(&iq, 0, None);
    assert!(frames.is_empty() && said.is_empty(), "no keys: as it always was");
    let (frames, said) = decode(&iq, 0, Some(keys(0x81, 8, &des)));
    assert!(frames.is_empty(), "another key id");
    assert_eq!(said, [(0x81, 7, false)], "the call names key id 7, which isn't held");
    let (frames, _) = decode(&iq, 0, Some(keys(0x81, 7, &[0x11; 8])));
    assert!(frames != clear_frames(0..18 * SUPERFRAMES));
}

/// Joined at the start of a superframe with no PTT: the cipher is learned at its ESS, and the
/// frames held until then are decrypted (or, clear, released a little late).
#[test]
fn a_call_joined_at_a_superframe_start_loses_nothing() {
    let des = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let (frames, said) = decode(&air(&call(Some((0x81, 7, &des)), Start::Ldu1, 0)), 0, Some(keys(0x81, 7, &des)));
    let want = clear_frames(0..18 * SUPERFRAMES);
    assert!(frames == want, "{}", differing(&frames, &want));
    assert_eq!(said, [(0x81, 7, true)]);
    // A clear call, with keys loaded: all of it, the first superframe a little late.
    let (frames, said) = decode(&air(&call(None, Start::Ldu1, 0)), 0, Some(keys(0x81, 7, &des)));
    assert!(frames == want, "clear: {}", differing(&frames, &want));
    assert!(said.is_empty());
    // And with no keys loaded, as it always was: no frames are held, so all come out at once.
    let (frames, _) = decode(&air(&call(None, Start::Ldu1, 0)), 0, None);
    assert!(frames == want, "no keys: {}", differing(&frames, &want));
}

/// Joined part-way through a superframe: its earlier 4V frames can't be placed, so (encrypted) they
/// are dropped, not decrypted into noise; from its 2V burst on everything is.
#[test]
fn a_call_joined_part_way_through_a_superframe_is_decrypted_from_its_2v_burst() {
    let des = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let (frames, _) = decode(&air(&call(Some((0x81, 7, &des)), Start::Ldu2, 0)), 0, Some(keys(0x81, 7, &des)));
    let want = clear_frames(16..18 * SUPERFRAMES);
    assert!(frames == want, "{}", differing(&frames, &want));
}
