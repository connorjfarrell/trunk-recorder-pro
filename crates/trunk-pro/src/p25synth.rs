//! `trunk-pro tool p25synth <out.cu8> [--phase2 [--channel 0|1] [--sysid N --wacn N]] [--center Hz]
//! [--freq Hz] [--rate Hz] [--nac N] [--tg N] [--src N] [--superframes N] [--join header|ldu1|ldu2]
//! [--algid N --kid N (--key hex | --ekc file [--password-file file]) [--mi hex]]` — a synthetic P25
//! call as a capture (rtl_sdr's cu8), in noise: one channel at `--freq`, Phase 1 (C4FM) or, with
//! `--phase2`, one logical channel of a Phase 2 (H-DQPSK) voice channel (decode it with `tool p2
//! --nac N --sysid N --wacn N`). With `--algid` its voice is
//! encrypted: under `--key`, or the key the container holds for that algorithm and key id, so
//! a capture made from a container is decrypted by the same container. Its voice is a test
//! pattern, not speech. `--key` puts a key on the command line (visible to other users of the
//! computer): for test keys; a real key comes from `--ekc`. For checking a setup end to end (`replay --p25 <freq> --ekc …`), or
//! another decoder against this one.

use std::io::{BufWriter, Write};

use num_complex::Complex32;
use trunk_core::p25::synth::{imbe, modulate, Call, Crypt, Start};

use crate::{die, Args};

/// Hex digits as bytes. A bad value is reported without being repeated: it may be a key.
fn hex(s: &str, what: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let bad = || -> ! { die(&format!("--{what}: not an even number of hex digits")) };
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        bad();
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|_| bad())).collect()
}

/// A numeric identifier option (decimal or 0x…): present when `required`, a whole number, and at most `max`.
/// (A number that doesn't fit is an error, not wrapped into another one: `--algid 0x184` is not AES.)
fn ident(a: &Args, name: &str, max: u32, default: Option<u32>) -> u32 {
    let Some(raw) = a.get(name) else {
        return default.unwrap_or_else(|| die(&format!("--{name} is needed")));
    };
    let raw = raw.trim();
    let v = if let Some(h) = raw.strip_prefix("0x") { u64::from_str_radix(h, 16) } else { raw.parse() };
    match v {
        Ok(v) if v <= max as u64 => v as u32,
        Ok(_) => die(&format!("--{name} {raw}: at most {max:#x}")),
        Err(_) => die(&format!("--{name} {raw}: not a whole number")),
    }
}

pub fn run(a: &Args) {
    let path = a.positional.get(1).unwrap_or_else(|| die("tool p25synth <out.cu8> [--center Hz] [--freq Hz] …"));
    let center = a.num("center", 155_150_000.0);
    let freq = a.num("freq", 155_200_000.0);
    let fs = a.num("rate", 2_400_000.0);
    // (`--join`: `--start` is a flag of other commands, which takes no value.)
    let start = match a.get("join").unwrap_or("header") {
        "header" => Start::Header,
        "ldu1" => Start::Ldu1,
        "ldu2" => Start::Ldu2,
        s => die(&format!("--join {s}: header, ldu1 or ldu2")),
    };
    let crypt = a.get("algid").map(|_| {
        let algid = ident(a, "algid", 0xff, None) as u8;
        let kid = ident(a, "kid", 0xffff, None) as u16;
        let key = match (a.get("key"), a.get("ekc")) {
            (Some(k), _) => zeroize::Zeroizing::new(hex(k, "key")),
            (None, Some(ekc)) => {
                let settings = trunk_app::config::KeysSettings { ekc_file: ekc.into(), password_file: a.get("password-file").unwrap_or("").into(), ..Default::default() };
                let loaded = crate::keyfiles::load(&settings, std::path::Path::new("."));
                for (_, t) in &loaded.notes {
                    eprintln!("{t}");
                }
                let store = loaded.keys.unwrap_or_else(|| die("--ekc: no keys loaded"));
                zeroize::Zeroizing::new(store.get(algid, kid).unwrap_or_else(|| die(&format!("--ekc: no key for algorithm {algid:#04x}, key id {kid}"))).bytes().to_vec())
            }
            _ => die("--algid needs --key hex, or --ekc <file> --password-file <file>"),
        };
        let mi = a.get("mi").map(|m| hex(m, "mi")).unwrap_or_else(|| vec![0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]);
        if mi.len() != 8 {
            die("--mi: 8 octets (16 hex digits)");
        }
        let mut m = [0u8; 9];
        m[..8].copy_from_slice(&mi);
        Crypt { algid, kid, key, mi: m }
    });
    if a.flag("phase2") {
        return run_phase2(a, path, center, freq, fs, start, crypt);
    }
    let call = Call { nac: ident(a, "nac", 0xfff, Some(0x293)) as u16, tgid: ident(a, "tg", 0xffff, Some(1001)) as u16, source: ident(a, "src", 0xff_ffff, Some(4_567_890)), crypt, superframes: a.num("superframes", 5.0) as usize, start };
    let frames = call.frames(imbe).unwrap_or_else(|e| die(&format!("{e}")));

    // 120 ms of alternating outer symbols (a key-up), the call, then silence for the call to end.
    let mut dibits: Vec<u8> = (0..576).map(|i| if i % 2 == 0 { 0b01 } else { 0b11 }).collect();
    dibits.extend(frames.into_iter().flatten());
    let mut noise = Noise::new();
    let mut iq = noise.take((fs * 0.5) as usize);
    let mut phase = 0.0;
    let mut tx = modulate(&dibits, fs, freq - center, 0.25, &mut phase);
    for (t, n) in tx.iter_mut().zip(noise.take(dibits.len() * (fs / 4800.0) as usize + 1)) {
        *t += n;
    }
    iq.extend(tx);
    iq.extend(noise.take((fs * 2.5) as usize));
    write_cu8(path, &iq);
    eprintln!(
        "{path}: {:.1} s at {fs} S/s, centre {center} Hz; channel {freq} Hz, NAC {:#x}, talkgroup {}, {} superframes{}",
        iq.len() as f64 / fs,
        call.nac,
        call.tgid,
        call.superframes,
        call.crypt.as_ref().map_or(String::new(), |c| format!(", encrypted: algorithm {:#04x}, key id {}", c.algid, c.kid))
    );
}

/// Gaussian noise (σ 0.01 per axis), the same sequence every run.
struct Noise(u64);

impl Noise {
    fn new() -> Self {
        Noise(0x2545_f491_4f6c_dd1d)
    }

    fn uniform(&mut self) -> f64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        ((self.0 >> 11) as f64 + 0.5) / (1u64 << 53) as f64
    }

    fn take(&mut self, n: usize) -> Vec<Complex32> {
        (0..n)
            .map(|_| {
                let (x, y) = (self.uniform(), self.uniform());
                let r = (-2.0 * x.ln()).sqrt() * 0.01;
                let t = 2.0 * std::f64::consts::PI * y;
                Complex32::new((r * t.cos()) as f32, (r * t.sin()) as f32)
            })
            .collect()
    }
}

/// Write `iq` as rtl_sdr's unsigned 8-bit I/Q.
fn write_cu8(path: &str, iq: &[Complex32]) {
    let mut w = BufWriter::new(std::fs::File::create(path).unwrap_or_else(|e| die(&format!("{path}: {e}"))));
    for v in iq {
        w.write_all(&[(v.re * 127.5 + 127.5).clamp(0.0, 255.0) as u8, (v.im * 127.5 + 127.5).clamp(0.0, 255.0) as u8]).unwrap_or_else(|e| die(&format!("{path}: {e}")));
    }
    w.flush().unwrap_or_else(|e| die(&format!("{path}: {e}")));
}

fn run_phase2(a: &Args, path: &str, center: f64, freq: f64, fs: f64, start: Start, crypt: Option<Crypt>) {
    use trunk_core::nxdn::synth::ambe;
    use trunk_core::p25::synth_p2::{modulate, Call};
    let call = Call {
        nac: ident(a, "nac", 0xfff, Some(0x293)),
        sys_id: ident(a, "sysid", 0xfff, Some(0x2a5)),
        wacn: ident(a, "wacn", 0xf_ffff, Some(0xbee00)),
        tgid: ident(a, "tg", 0xffff, Some(1001)) as u16,
        source: ident(a, "src", 0xff_ffff, Some(4_567_890)),
        crypt,
        superframes: a.num("superframes", 5.0) as usize,
        channel: match a.num("channel", 0.0) {
            c if c == 0.0 || c == 1.0 => c as usize,
            _ => die("--channel: 0 or 1"),
        },
        start,
    };
    if (fs / 6000.0).fract() != 0.0 {
        die("--rate: a whole number of samples per symbol at 6000 baud (a multiple of 6000)");
    }
    let dibits = call.dibits(ambe).unwrap_or_else(|e| die(&format!("{e}")));
    let mut noise = Noise::new();
    let mut iq = noise.take((fs * 0.3) as usize);
    let mut phase = 0.0;
    let mut tx = modulate(&dibits, fs, freq - center, 0.25, &mut phase);
    for (t, n) in tx.iter_mut().zip(noise.take(tx_len(&dibits, fs))) {
        *t += n;
    }
    iq.extend(tx);
    iq.extend(noise.take((fs * 0.5) as usize));
    write_cu8(path, &iq);
    eprintln!(
        "{path}: {:.1} s at {fs} S/s, centre {center} Hz; Phase 2 channel {freq} Hz, logical channel {}, NAC {:#x}, system {:#x}, WACN {:#x}, talkgroup {}, {} superframes{}",
        iq.len() as f64 / fs,
        call.channel,
        call.nac,
        call.sys_id,
        call.wacn,
        call.tgid,
        call.superframes,
        call.crypt.as_ref().map_or(String::new(), |c| format!(", encrypted: algorithm {:#04x}, key id {}", c.algid, c.kid))
    );
}

/// How many samples the modulated call has (its symbols, and the pulse filter's tail).
fn tx_len(dibits: &[u8], fs: f64) -> usize {
    let sps = (fs / 6000.0) as usize;
    dibits.len() * sps + 8 * sps + 1
}

