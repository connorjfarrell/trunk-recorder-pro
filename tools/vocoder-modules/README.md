# Vocoder modules

The module SDK and two example vocoder modules for Trunk Recorder Pro. A module is a program the
recorder starts to decode vocoder frames in place of its built-in decoders; see the
[user guide](../../docs/guides/vocoder-modules.md) and the
[protocol](../../docs/developer/vocoder-modules.md).

| Folder | |
|---|---|
| `sdk/` | `vocoder-module-sdk`: the stdio protocol; implement `Vocoder` and call `serve` |
| `blip25-vocoder/` | IMBE and AMBE+2 through openBLIP25's [blip25-vocoder](https://github.com/openBLIP25/blip25-vocoder) |
| `blip25-mbe/` | IMBE through openBLIP25's [blip25-mbe](https://github.com/openBLIP25/blip25-mbe) |

This is not part of the app's build, and the app contains none of the code the example modules
depend on. **Both blip25 projects' `PATENT_NOTICE.md` say their synthesis core was reverse-engineered
from a compiled reference vocoder and is patent-encumbered, IMBE included, offered for research and
interoperability study.** Read them before building one; building and installing it is your choice.

## Build and install

```
cargo build --release
```

Then copy a module's program and its `module.json` into `vocoders/<id>/` beside the recorder's
config file (the program named for the folder, `.exe` on Windows):

```
mkdir -p ~/.config/trunk-pro/vocoders/blip25-vocoder
cp target/release/blip25-vocoder blip25-vocoder/module.json ~/.config/trunk-pro/vocoders/blip25-vocoder/
```

and choose **External module…** in Setup (or `"vocoder": "module:blip25-vocoder"`).

## Your own module

```rust
use vocoder_module_sdk::{serve, Kind, Vocoder, FRAME_SAMPLES};
struct Mine;
impl Vocoder for Mine {
    fn imbe(&mut self, bits: &[u8; 88], e0: u8, et: u8, erased: bool) -> (Kind, [i16; FRAME_SAMPLES]) { /* … */ }
}
fn main() { serve(Mine); }
```

For hardware (a DVSI dongle) open the device before `serve`, call `vocoder_module_sdk::fail("why")`
if it isn't there, and put its channel count in `module.json` as `maxStreams`.
