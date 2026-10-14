//! Vocoder modules: programs (or hardware behind one, such as a DVSI USB
//! dongle) that turn vocoder frames into audio in place of a built-in decoder.
//! The user installs one in `vocoders/<id>/` beside the config and names it in
//! `recording.vocoder` as `module:<id>`. The protocol is
//! docs/developer/vocoder-modules.md. Each decoding stream (a call, or a
//! timeslot of one) gets its own process; a module that fails costs the rest of
//! that stream a built-in vocoder, never the call.

use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::time::Duration;

use serde::Deserialize;
use trunk_core::mbe::external::{self, Codec, External, Provider};
use trunk_core::mbe::{Kind, FRAME_SAMPLES};

/// How long a module has to say it is ready (a dongle opens a serial port).
const READY_TIMEOUT: Duration = Duration::from_secs(3);
/// How long it has to answer one frame. A frame is 20 ms of audio.
const REPLY_TIMEOUT: Duration = Duration::from_millis(500);
/// kind + 160 little-endian i16.
const REPLY_LEN: usize = 1 + FRAME_SAMPLES * 2;
/// mbelib's float scale is the sample ÷ 7 (the decoder's limiter multiplies by 7).
const SCALE: f32 = 1.0 / 7.0;

const OP_IMBE: u8 = 1;
const OP_AMBE: u8 = 2;
const FLAG_ERASED: u8 = 1;

/// The folder modules are installed in.
pub fn modules_dir() -> PathBuf {
    crate::paths::data_dir().join("vocoders")
}

/// `module.json`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Manifest {
    pub name: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub description: String,
    /// "imbe" and/or "ambe".
    pub codecs: Vec<String>,
    /// How many streams the module can decode at once (a dongle's channels);
    /// absent: no limit.
    #[serde(default)]
    pub max_streams: Option<usize>,
}

impl Manifest {
    fn does(&self, codec: Codec) -> bool {
        let want = match codec {
            Codec::Imbe => "imbe",
            Codec::Ambe => "ambe",
        };
        self.codecs.iter().any(|c| c.eq_ignore_ascii_case(want))
    }
}

/// Install a module for the config's `recording.vocoder`, or none: call it
/// before every session start. Never fails the start: a module that can't be
/// used is logged and the built-in decoder is used.
pub fn select(vocoder: &str) {
    select_in(&modules_dir(), vocoder);
}

/// [`select`], with the modules in `root`.
pub fn select_in(root: &Path, vocoder: &str) {
    external::set_provider(None);
    let Some(id) = vocoder.get(..7).filter(|p| p.eq_ignore_ascii_case("module:")).map(|_| &vocoder[7..]) else { return };
    match Module::find(root, id) {
        Ok(m) => {
            log::info!(
                "vocoder module {id} ({}): {}{}",
                m.manifest.name,
                m.manifest.codecs.join(", "),
                m.manifest.max_streams.map_or(String::new(), |n| format!(", at most {n} at once"))
            );
            external::set_provider(Some(Arc::new(m)));
        }
        Err(e) => log::warn!("vocoder module {id}: {e}; using the built-in vocoder"),
    }
}

/// An installed module.
pub struct Module {
    id: String,
    exe: PathBuf,
    dir: PathBuf,
    pub manifest: Manifest,
    active: Arc<AtomicUsize>,
    told_busy: AtomicBool,
}

impl Module {
    pub fn find(root: &Path, id: &str) -> Result<Module, String> {
        if id.is_empty() || id.len() > 64 || id.starts_with('.') || !id.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.')) {
            return Err("the module's name must be letters, digits, - _ . only".into());
        }
        // Absolute: the module runs with its own folder as the working directory,
        // where a relative path to its program would point elsewhere.
        let dir = std::path::absolute(root.join(id)).map_err(|e| format!("{}: {e}", root.display()))?;
        let manifest_path = dir.join("module.json");
        let text = std::fs::read_to_string(&manifest_path).map_err(|e| format!("{}: {e}", manifest_path.display()))?;
        let manifest: Manifest = serde_json::from_str(&text).map_err(|e| format!("{}: {e}", manifest_path.display()))?;
        if manifest.codecs.is_empty() {
            return Err("module.json lists no codecs".into());
        }
        let exe = dir.join(if cfg!(windows) { format!("{id}.exe") } else { id.to_string() });
        if !exe.is_file() {
            return Err(format!("{} isn't there", exe.display()));
        }
        Ok(Module { id: id.to_string(), exe, dir, manifest, active: Arc::new(AtomicUsize::new(0)), told_busy: AtomicBool::new(false) })
    }
}

impl Provider for Module {
    fn supports(&self, codec: Codec) -> bool {
        self.manifest.does(codec)
    }

    fn open(&self, codec: Codec) -> Option<Box<dyn External>> {
        if !self.manifest.does(codec) {
            return None;
        }
        let slot = Slot::take(&self.active, self.manifest.max_streams);
        let Some(slot) = slot else {
            if !self.told_busy.swap(true, Ordering::Relaxed) {
                log::info!("vocoder module {}: all {} of its streams are busy; other calls use the built-in vocoder", self.id, self.manifest.max_streams.unwrap_or(0));
            }
            return None;
        };
        match Stream::spawn(&self.id, &self.exe, &self.dir, slot) {
            Ok(s) => Some(Box::new(s)),
            Err(e) => {
                log::warn!("vocoder module {}: {e}", self.id);
                None
            }
        }
    }
}

/// One of the module's `maxStreams`, held while a stream is open.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(active: &Arc<AtomicUsize>, max: Option<usize>) -> Option<Slot> {
        let n = active.fetch_add(1, Ordering::SeqCst);
        if max.is_some_and(|m| n >= m) {
            active.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Slot(active.clone()))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

enum Event {
    Ready,
    Failed(String),
    Reply(Vec<u8>),
    Closed,
}

/// One module process.
struct Stream {
    id: String,
    child: Child,
    stdin: Option<ChildStdin>,
    rx: Receiver<Event>,
    ready: bool,
    dead: bool,
    _slot: Slot,
}

impl Stream {
    fn spawn(id: &str, exe: &Path, dir: &Path, slot: Slot) -> Result<Stream, String> {
        let mut child = Command::new(exe)
            .current_dir(dir)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| format!("can't start {}: {e}", exe.display()))?;
        let stdin = child.stdin.take();
        let stdout = child.stdout.take().ok_or("no stdout")?;
        let stderr = child.stderr.take().ok_or("no stderr")?;
        let (tx, rx) = channel();
        std::thread::spawn(move || {
            let mut out = BufReader::new(stdout);
            let mut line = String::new();
            let first = match out.read_line(&mut line) {
                Ok(n) if n > 0 => serde_json::from_str::<serde_json::Value>(line.trim()).ok(),
                _ => None,
            };
            match first.as_ref().and_then(|v| v["type"].as_str()) {
                Some("ready") => {
                    let _ = tx.send(Event::Ready);
                }
                Some("error") => {
                    let _ = tx.send(Event::Failed(first.as_ref().and_then(|v| v["message"].as_str()).unwrap_or("it reported an error").to_string()));
                    return;
                }
                _ => {
                    let _ = tx.send(Event::Failed("it didn't say it was ready".into()));
                    return;
                }
            }
            loop {
                let mut buf = vec![0u8; REPLY_LEN];
                if out.read_exact(&mut buf).is_err() || tx.send(Event::Reply(buf)).is_err() {
                    let _ = tx.send(Event::Closed);
                    return;
                }
            }
        });
        let name = id.to_string();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                log::info!("vocoder module {name}: {line}");
            }
        });
        Ok(Stream { id: id.to_string(), child, stdin, rx, ready: false, dead: false, _slot: slot })
    }

    fn fail(&mut self, why: &str) {
        if !self.dead {
            log::warn!("vocoder module {}: {why}; the rest of this stream uses the built-in vocoder", self.id);
            self.dead = true;
            self.stdin = None;
            let _ = self.child.kill();
        }
    }

    /// One request and its reply: `(kind, samples)`.
    fn call(&mut self, op: u8, flags: u8, e0: u8, et: u8, payload: &[u8]) -> Option<(u8, [i16; FRAME_SAMPLES])> {
        if self.dead {
            return None;
        }
        if !self.ready {
            match self.rx.recv_timeout(READY_TIMEOUT) {
                Ok(Event::Ready) => self.ready = true,
                Ok(Event::Failed(m)) => {
                    self.fail(&m);
                    return None;
                }
                _ => {
                    self.fail("it didn't start in time");
                    return None;
                }
            }
        }
        let mut req = Vec::with_capacity(4 + payload.len());
        req.extend_from_slice(&[op, flags, e0, et]);
        req.extend_from_slice(payload);
        let sent = self.stdin.as_mut().is_some_and(|w| w.write_all(&req).and_then(|_| w.flush()).is_ok());
        if !sent {
            self.fail("it stopped reading");
            return None;
        }
        match self.rx.recv_timeout(REPLY_TIMEOUT) {
            Ok(Event::Reply(r)) => {
                let mut pcm = [0i16; FRAME_SAMPLES];
                for (s, b) in pcm.iter_mut().zip(r[1..].chunks_exact(2)) {
                    *s = i16::from_le_bytes([b[0], b[1]]);
                }
                Some((r[0], pcm))
            }
            Ok(Event::Closed) | Err(RecvTimeoutError::Disconnected) => {
                self.fail("it exited");
                None
            }
            Ok(Event::Failed(m)) => {
                self.fail(&m);
                None
            }
            Ok(Event::Ready) | Err(RecvTimeoutError::Timeout) => {
                self.fail("it stopped answering");
                None
            }
        }
    }

    fn frame(&mut self, op: u8, flags: u8, e0: u32, et: u32, payload: &[u8], out: &mut [f32; FRAME_SAMPLES]) -> Option<Kind> {
        let (kind, pcm) = self.call(op, flags, e0.min(255) as u8, et.min(255) as u8, payload)?;
        let kind = match kind {
            0 => Kind::Voice,
            1 => Kind::Repeat,
            2 => Kind::Muted,
            3 => Kind::Erasure,
            4 => Kind::Tone,
            // Out of step or garbled: not a stream to trust any longer.
            other => {
                self.fail(&format!("it answered with an unknown frame kind ({other})"));
                return None;
            }
        };
        for (o, &v) in out.iter_mut().zip(pcm.iter()) {
            *o = v as f32 * SCALE;
        }
        Some(kind)
    }
}

impl External for Stream {
    fn imbe(&mut self, d: &[u8; 88], e0: u32, et: u32, erased: bool, out: &mut [f32; FRAME_SAMPLES]) -> Option<Kind> {
        self.frame(OP_IMBE, if erased { FLAG_ERASED } else { 0 }, e0, et, d, out)
    }

    fn ambe(&mut self, d: &[u8; 49], errs: u32, out: &mut [f32; FRAME_SAMPLES]) -> Option<Kind> {
        self.frame(OP_AMBE, 0, 0, errs, d, out)
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        // Closing stdin asks it to exit; the kill is for one that doesn't.
        self.stdin = None;
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A module folder with a shell script as its program.
    fn install(tag: &str, max: Option<usize>, script: &str) -> (PathBuf, Module) {
        let root = std::env::temp_dir().join(format!("trunk-pro-vocoder-{tag}-{}", std::process::id()));
        let dir = root.join("t");
        std::fs::create_dir_all(&dir).unwrap();
        let max = max.map_or(String::new(), |n| format!(r#", "maxStreams": {n}"#));
        std::fs::write(dir.join("module.json"), format!(r#"{{"name": "test", "codecs": ["imbe"]{max}}}"#)).unwrap();
        std::fs::write(dir.join("t"), script).unwrap();
        std::fs::set_permissions(dir.join("t"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let m = Module::find(&root, "t").unwrap();
        (root, m)
    }

    /// Answers every 92-byte IMBE request with "repeat" and a ramp-free silence.
    const ECHO: &str = r#"#!/bin/sh
echo '{"type":"ready"}'
while true; do
  n=$(dd bs=92 count=1 iflag=fullblock 2>/dev/null | wc -c)
  [ "$n" -eq 92 ] || exit 0
  printf '\001'
  head -c 320 /dev/zero
done
"#;

    #[test]
    fn frames_round_trip_and_streams_are_limited() {
        let (root, m) = install("echo", Some(1), ECHO);
        let mut a = m.open(Codec::Imbe).expect("first stream");
        assert!(m.open(Codec::Imbe).is_none(), "maxStreams 1: a second stream is refused");
        assert!(m.open(Codec::Ambe).is_none(), "the manifest lists imbe only");
        let mut out = [1f32; FRAME_SAMPLES];
        for _ in 0..3 {
            assert_eq!(a.imbe(&[0; 88], 0, 0, false, &mut out), Some(Kind::Repeat));
        }
        assert!(out.iter().all(|&v| v == 0.0));
        drop(a);
        assert!(m.open(Codec::Imbe).is_some(), "the slot is free again once the stream is dropped");
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn a_module_that_cannot_start_is_a_failed_stream() {
        let (root, m) = install("err", None, "#!/bin/sh\necho '{\"type\":\"error\",\"message\":\"no dongle\"}'\n");
        let mut s = m.open(Codec::Imbe).expect("spawns");
        let mut out = [0f32; FRAME_SAMPLES];
        assert_eq!(s.imbe(&[0; 88], 0, 0, false, &mut out), None);
        assert_eq!(s.imbe(&[0; 88], 0, 0, false, &mut out), None, "stays failed");
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn an_unknown_frame_kind_fails_the_stream() {
        let script = ECHO.replace("printf '\\001'", "printf '\\007'");
        assert_ne!(script, ECHO);
        let (root, m) = install("kind", None, &script);
        let mut s = m.open(Codec::Imbe).expect("spawns");
        let mut out = [0f32; FRAME_SAMPLES];
        assert_eq!(s.imbe(&[0; 88], 0, 0, false, &mut out), None);
        assert_eq!(s.imbe(&[0; 88], 0, 0, false, &mut out), None, "stays failed");
        std::fs::remove_dir_all(root).ok();
    }

    #[test]
    fn a_relative_modules_folder_works() {
        let (root, _) = install("rel", None, ECHO);
        // The same folder, named relative to the current directory.
        let cwd = std::env::current_dir().unwrap();
        let rel = root.strip_prefix(&cwd).map(Path::to_path_buf).unwrap_or_else(|_| pathdiff(&root, &cwd));
        let m = Module::find(&rel, "t").unwrap();
        let mut s = m.open(Codec::Imbe).expect("spawns");
        let mut out = [0f32; FRAME_SAMPLES];
        assert_eq!(s.imbe(&[0; 88], 0, 0, false, &mut out), Some(Kind::Repeat));
        std::fs::remove_dir_all(root).ok();
    }

    /// `to` relative to `from`, both absolute.
    fn pathdiff(to: &Path, from: &Path) -> PathBuf {
        let (to, from): (Vec<_>, Vec<_>) = (to.components().collect(), from.components().collect());
        let common = to.iter().zip(&from).take_while(|(a, b)| a == b).count();
        let mut p: PathBuf = std::iter::repeat_n("..", from.len() - common).collect();
        p.extend(&to[common..]);
        p
    }

    #[test]
    fn module_names_cannot_leave_the_folder() {
        for bad in ["", "..", "../x", "a/b", ".hidden", "a b"] {
            assert!(Module::find(Path::new("/nonexistent"), bad).is_err(), "{bad:?}");
        }
    }
}
