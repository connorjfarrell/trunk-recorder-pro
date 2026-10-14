# Vocoder modules

A vocoder module is a program you install that turns a call's vocoder frames into audio, in place
of the built-in decoders. Use one to try another software vocoder, to run a vocoder you hold a
licence for, or to hand the frames to hardware such as a DVSI USB dongle.

Trunk Recorder Pro ships no modules and none of the code they use. You build or obtain a module
yourself and put it in a folder. The built-in decoders (`fixed`, `enhanced`, `mbelib`) are unchanged
and stay the default.

Modules run in the desktop app and the server (`trunk-pro serve`, including Docker). The
[browser version](../install/browser.md) can't start programs, so it has no modules and keeps using
the built-in decoders.

## Installing a module

A module is a folder in `vocoders/`, beside the config file (the same place as `plugins/`; on
Linux `~/.config/trunk-pro/vocoders/`), named for the module's id:

```
vocoders/
  blip25-vocoder/
    module.json
    blip25-vocoder        (blip25-vocoder.exe on Windows)
```

`module.json` says what the module does:

| Field | |
|---|---|
| `name` | A name for the log |
| `description` | Optional |
| `codecs` | `"imbe"` (P25 Phase 1) and/or `"ambe"` (P25 Phase 2, DMR, NXDN) |
| `maxStreams` | Optional. How many calls (or timeslots) it can decode at once, for a dongle with few channels. Without it, no limit |

Then choose it: in **Setup → Recording → P25 voice decoder** pick **External module…** and type
the folder name, or set `"vocoder": "module:blip25-vocoder"` in `recording` (see
[recording.md](../configuration/recording.md)). It takes effect when recording starts. A name that isn't a plain folder name (letters, digits,
`- _ .`, up to 64, not starting with a dot) stops the start with a message; a valid name with no
such folder just uses the built-in decoder, and says so in the log.

One setting covers every codec the module lists: with `"codecs": ["imbe", "ambe"]` it decodes
Phase 1 and also Phase 2, DMR and NXDN voice. A codec it doesn't list stays on the built-in decoder.

## If a module can't run

A call's audio never depends on a module. The recorder uses the built-in decoder (the log says
why) when:

- the module isn't installed or its `module.json` is wrong: for the whole run;
- it can't start (no dongle, a bad setting) or takes more than 3 seconds to say it is ready: for
  that call;
- it is busy (`maxStreams` calls are already using it): for the extra calls;
- it crashes, exits or takes more than half a second to answer a frame: for the rest of that call.

A module that is slow but answers in time still holds up the recorder's voice processing while it
works, so keep a module's per-frame time well under 20 ms, and a hardware one to few streams.

## The example modules

[tools/vocoder-modules](https://github.com/connorjfarrell/trunk-recorder-pro/tree/main/tools/vocoder-modules)
has the module SDK and two example modules, built from openBLIP25's
[blip25-vocoder](https://github.com/openBLIP25/blip25-vocoder) (IMBE and AMBE+2) and
[blip25-mbe](https://github.com/openBLIP25/blip25-mbe) (IMBE). You need a Rust toolchain. These commands are for Linux; on macOS or Windows put the same two files in a
`vocoders/blip25-vocoder/` folder beside your config file (on Windows the program is
`blip25-vocoder.exe`):

```
cd tools/vocoder-modules
cargo build --release
mkdir -p ~/.config/trunk-pro/vocoders/blip25-vocoder
cp target/release/blip25-vocoder blip25-vocoder/module.json ~/.config/trunk-pro/vocoders/blip25-vocoder/
```

**Read their patent notices first.** Both projects' `PATENT_NOTICE.md` say their synthesis core was
reverse-engineered from a compiled reference vocoder, is patent-encumbered (IMBE as well as
AMBE+2), and is offered for research and interoperability study; anyone depending on them takes
that on themselves. That is why Trunk Recorder Pro doesn't include them: building and installing
one is your choice.

## Hardware and licensed libraries

The protocol doesn't care what is behind the program. A module for a DVSI AMBE-3000 USB dongle
opens its serial port and forwards frames to the chip; a module for a vendor library you are
licensed to use loads it and calls it. Set `maxStreams` to what the device can do at once. None are
included, and the example modules are the only ones tested. Write one with the
[module protocol](../developer/vocoder-modules.md).
