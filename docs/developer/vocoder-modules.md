# Vocoder module protocol

How a vocoder module talks to the recorder. For installing and choosing one see the
[user guide](../guides/vocoder-modules.md). The Rust SDK in `tools/vocoder-modules/sdk` implements
all of this; a module in another language needs only the rest of this page.

The recorder starts one **process per decoding stream** (a call, or one timeslot of one), so a
module's state is just that stream's. It runs `vocoders/<id>/<id>` (`<id>.exe` on Windows) with the
module's folder as its working directory, and talks over stdin and stdout. Stderr lines go to the
recorder's log. Closing stdin is the signal to exit (the recorder also kills a process that
doesn't).

## `module.json`

```json
{ "name": "…", "description": "…", "codecs": ["imbe", "ambe"], "maxStreams": 1 }
```

`maxStreams` is checked before a process is started, so a module holding a device (a serial port)
is never started twice over its limit.

## Startup

The module writes one line of JSON to stdout once it can decode:

```json
{"type":"ready"}
```

or, if it can't (no device, a bad setting) and then exits:

```json
{"type":"error","message":"no dongle found"}
```

It has 3 seconds. The recorder sends nothing before the ready line is read.

## Requests

Binary, on stdin. Every request is a 4-byte header and an optional payload:

| Byte | |
|---|---|
| 0 | `op`: 1 IMBE frame, 2 AMBE+2 frame, 3 reset |
| 1 | flags: bit 0 set means the frame was **lost** (the payload is meaningless) |
| 2 | `e0`: FEC errors corrected in the first codeword (IMBE; 0 for AMBE+2), saturated at 255 |
| 3 | `et`: FEC errors corrected in the whole frame, saturated at 255 |

- **IMBE (op 1)**: 88 payload bytes, the frame's 88 information bits, one per byte (0 or 1), in
  mbelib's `imbe_d` order: u0 u1 u2 u3 (12 bits each), u4 u5 u6 (11 each), u7 (7), most
  significant bit first.
- **AMBE+2 (op 2)**: 49 payload bytes, mbelib's `ambe_d`: u0 (12) u1 (12) u2 (11) u3 (14).
- **Reset (op 3)**: no payload. A new call begins on this stream.

These are the bits after the recorder's own FEC. Frames of an encrypted call arrive decrypted if
the recorder has the key.

## Replies

For every request, exactly one reply of 321 bytes on stdout, in order:

| Bytes | |
|---|---|
| 0 | kind: 0 voice, 1 repeat (the previous audio held because this frame was unusable), 2 muted, 3 erasure, 4 tone |
| 1–320 | 160 samples of 16-bit little-endian PCM: 20 ms at 8 kHz, full scale 32767 |

A reset gets a reply too (any content). The recorder counts repeat, muted and erasure frames as a
call's bad frames, and applies its own loudness and limiting to the samples.

A module should answer within a few milliseconds. The recorder waits 500 ms; if it gets no reply, or
the module exits, writes garbage, or closes stdout, it stops using the module for that stream and
decodes the rest of it with a built-in vocoder.

## Testing a module

`trunk-pro tool revoice <call.sdr | call.frames.jsonl> <out.wav> --profile module:<id>
[--modules-dir DIR]` decodes a saved frame capture (the **Save vocoder frames** setting) through a
module, with the built-in decoder taking over where it fails; compare it with `--profile fixed`.
