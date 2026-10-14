//! Vocoders that live outside the app ("vocoder modules"): a program the user
//! installs, or hardware such as a DVSI USB dongle behind one. This is only the
//! hook. The app registers a [`Provider`] when the config names a module
//! (`recording.vocoder` = `module:<id>`), and a [`super::Decoder`] asks it for
//! a stream when it is made. Nothing here spawns anything, so trunk-core stays
//! platform-independent (the browser build never registers a provider).
//!
//! A module that fails (won't start, crashes, stops answering) returns `None`
//! from a call; the decoder drops it and carries on with a built-in vocoder, so
//! a bad module costs some audio, never a call.

use std::sync::{Arc, RwLock};

use super::{Kind, FRAME_SAMPLES};

/// Which codec a stream decodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Codec {
    /// IMBE 7200x4400 (P25 Phase 1).
    Imbe,
    /// AMBE+2 3600x2450 (P25 Phase 2, DMR, NXDN).
    Ambe,
}

/// One external decoding stream: one call, or one timeslot of one.
pub trait External: Send {
    /// 88 information bits (mbelib's imbe_d) → 160 samples at mbelib's float
    /// scale (the decoder's [`super::to_limited`] expects it). `None`: this
    /// stream failed and is finished.
    fn imbe(&mut self, d: &[u8; 88], e0: u32, et: u32, erased: bool, out: &mut [f32; FRAME_SAMPLES]) -> Option<Kind>;
    /// 49 AMBE+2 information bits (mbelib's ambe_d) and the FEC error count.
    fn ambe(&mut self, d: &[u8; 49], errs: u32, out: &mut [f32; FRAME_SAMPLES]) -> Option<Kind>;
    /// A new call: forget the previous one's state.
    fn reset(&mut self);
}

/// Opens streams on the module the config chose.
pub trait Provider: Send + Sync {
    /// A new stream for `codec`, or `None` when the module doesn't do that
    /// codec, is busy (a dongle has few channels), or won't start. The
    /// decoder then uses a built-in vocoder.
    fn open(&self, codec: Codec) -> Option<Box<dyn External>>;
}

static PROVIDER: RwLock<Option<Arc<dyn Provider>>> = RwLock::new(None);

/// Use `provider` for the decoders made from now on (`None`: none). Call it
/// before the session starts; streams already open keep their module.
pub fn set_provider(provider: Option<Arc<dyn Provider>>) {
    *PROVIDER.write().unwrap_or_else(|e| e.into_inner()) = provider;
}

pub(super) fn open(codec: Codec) -> Option<Box<dyn External>> {
    let p = PROVIDER.read().unwrap_or_else(|e| e.into_inner()).clone()?;
    p.open(codec)
}
