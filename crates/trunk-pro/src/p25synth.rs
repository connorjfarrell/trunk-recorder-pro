//! `trunk-pro tool p25synth <out.cu8> [--center Hz] [--freq Hz] [--rate Hz] [--nac N] [--tg N]
//! [--src N] [--superframes N] [--start header|ldu1|ldu2] [--algid N --kid N (--key hex | --ekc
//! file [--password-file file]) [--mi hex]]` — a synthetic P25 Phase 1 call as a capture
//! (rtl_sdr's cu8), in noise: one conventional channel at `--freq`. With `--algid` its voice is
//! encrypted: under `--key`, or the key the container holds for that algorithm and key id, so
//! a capture made from a container is decrypted by the same container. Its voice is a test
//! pattern, not speech. For checking a setup end to end (`replay --p25 <freq> --ekc …`), or
//! another decoder against this one.

use std::io::{BufWriter, Write};

use num_complex::Complex32;
use trunk_core::p25::synth::{imbe, modulate, Call, Crypt, Start};

use crate::{die, Args};

fn hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        die(&format!("not hex: {s}"));
    }
    (0..s.len()).step_by(2).map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap_or_else(|_| die(&format!("not hex: {s}")))).collect()
}

pub fn run(a: &Args) {
    let path = a.positional.get(1).unwrap_or_else(|| die("tool p25synth <out.cu8> [--center Hz] [--freq Hz] …"));
    let center = a.num("center", 155_150_000.0);
    let freq = a.num("freq", 155_200_000.0);
    let fs = a.num("rate", 2_400_000.0);
    let start = match a.get("start").unwrap_or("header") {
        "header" => Start::Header,
        "ldu1" => Start::Ldu1,
        "ldu2" => Start::Ldu2,
        s => die(&format!("--start {s}: header, ldu1 or ldu2")),
    };
    let crypt = a.get("algid").map(|_| {
        let algid = crate::tool::num_any(a, "algid") as u8;
        let kid = crate::tool::num_any(a, "kid") as u16;
        let key = match (a.get("key"), a.get("ekc")) {
            (Some(k), _) => hex(k),
            (None, Some(ekc)) => {
                let settings = trunk_app::config::KeysSettings { ekc_file: ekc.into(), password_file: a.get("password-file").unwrap_or("").into(), ..Default::default() };
                let loaded = crate::keyfiles::load(&settings, std::path::Path::new("."));
                for (_, t) in &loaded.notes {
                    eprintln!("{t}");
                }
                let store = loaded.keys.unwrap_or_else(|| die("--ekc: no keys loaded"));
                store.get(algid, kid).unwrap_or_else(|| die(&format!("--ekc: no key for algorithm {algid:#04x}, key id {kid}"))).bytes().to_vec()
            }
            _ => die("--algid needs --key hex, or --ekc <file> --password-file <file>"),
        };
        let mi = a.get("mi").map(hex).unwrap_or_else(|| vec![0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef]);
        if mi.len() != 8 {
            die("--mi: 8 octets (16 hex digits)");
        }
        let mut m = [0u8; 9];
        m[..8].copy_from_slice(&mi);
        Crypt { algid, kid, key, mi: m }
    });
    let call = Call { nac: if a.get("nac").is_some() { crate::tool::num_any(a, "nac") as u16 } else { 0x293 }, tgid: a.num("tg", 1001.0) as u16, source: a.num("src", 4_567_890.0) as u32, crypt, superframes: a.num("superframes", 5.0) as usize, start };
    let frames = call.frames(imbe).unwrap_or_else(|e| die(&format!("{e}")));

    // 120 ms of alternating outer symbols (a key-up), the call, then silence for the call to end.
    let mut dibits: Vec<u8> = (0..576).map(|i| if i % 2 == 0 { 0b01 } else { 0b11 }).collect();
    dibits.extend(frames.into_iter().flatten());
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
                let (x, y) = (u(), u());
                let r = (-2.0 * x.ln()).sqrt() * 0.01;
                let t = 2.0 * std::f64::consts::PI * y;
                Complex32::new((r * t.cos()) as f32, (r * t.sin()) as f32)
            })
            .collect()
    };
    let mut iq = noise((fs * 0.5) as usize);
    let mut phase = 0.0;
    let mut tx = modulate(&dibits, fs, freq - center, 0.25, &mut phase);
    for (t, n) in tx.iter_mut().zip(noise(dibits.len() * (fs / 4800.0) as usize + 1)) {
        *t += n;
    }
    iq.extend(tx);
    iq.extend(noise((fs * 2.5) as usize));
    let mut w = BufWriter::new(std::fs::File::create(path).unwrap_or_else(|e| die(&format!("{path}: {e}"))));
    for v in &iq {
        w.write_all(&[(v.re * 127.5 + 127.5).clamp(0.0, 255.0) as u8, (v.im * 127.5 + 127.5).clamp(0.0, 255.0) as u8]).unwrap_or_else(|e| die(&format!("{path}: {e}")));
    }
    w.flush().unwrap_or_else(|e| die(&format!("{path}: {e}")));
    eprintln!(
        "{path}: {:.1} s at {fs} S/s, centre {center} Hz; channel {freq} Hz, NAC {:#x}, talkgroup {}, {} superframes{}",
        iq.len() as f64 / fs,
        call.nac,
        call.tgid,
        call.superframes,
        call.crypt.as_ref().map_or(String::new(), |c| format!(", encrypted: algorithm {:#04x}, key id {}", c.algid, c.kid))
    );
}
