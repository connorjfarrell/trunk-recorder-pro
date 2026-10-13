# Encryption Keys

Trunk Recorder Pro can decrypt **P25 Phase 1 and Phase 2** calls when you hold the key, as a radio or console that
has been keyloaded does. It only uses keys you give it: nothing here recovers or guesses a key.
Calls whose key isn't loaded are handled as they always were (flagged encrypted, and not recorded
unless [`recordEncrypted`](recording.md#recording-keys) is on).

| Cipher | P25 algorithm id | Key |
|---|---|---|
| DES-OFB | `0x81` | 8 bytes |
| AES-256 | `0x84` | 32 bytes |
| ADP (Motorola, RC4) | `0xAA` | 5 bytes |

DMR and NXDN calls aren't decrypted. A key for another algorithm in your container
(3DES, Motorola DES-XL) is ignored, and the log says so.

**How well each is checked.** DES-OFB and AES-256 are checked against the worked examples in the
standards (TIA-102.AAAD and its Phase 2 edition AAAD-B: the keystream, the frame positions and the
encrypted frames) for both Phase 1 and Phase 2. Phase 1 DES-OFB, AES-256 and ADP are also checked
against captures from real radios, and Phase 2 AES-256 has been used on a live system's own traffic
with its keys (a Phase 2 trunked system, decoded with an SDRplay). DES-OFB on Phase 2 has not been
tried on a live system. ADP is Motorola's and isn't in the standards; on Phase 2 it uses
the layout op25 and DSD-FME share, and has not been checked against a Phase 2 radio. If a known-key
call decrypts to noise, tell us (with the algorithm, and a capture if you can).

## Setting it up

Keys come from a **KFDtool encrypted key container** (`.ekc`), made in
[KFDtool](https://github.com/KFDtool/KFDtool) with its password. Keep the password in a separate file:

```bash
printf '%s\n' 'the container password' > /etc/trunk-pro/keys.pw
chmod 600 /etc/trunk-pro/keys.pw
```

Then add a `keys` section to the config:

```json
"keys": {
  "ekcFile": "/etc/trunk-pro/keys.ekc",
  "passwordFile": "/etc/trunk-pro/keys.pw"
}
```

| Key | Required | Description |
|---|:---:|---|
| `ekcFile` | to decrypt | The container: absolute, or relative to the config file's folder |
| `allowLanUnlock` | optional | `true` lets a browser on a private-network address (not only this computer) unlock the container in Setup. Off by default, and set in the config file only: the interface is plain HTTP with no login, so the password crosses the network unencrypted and anyone on that network can try to unlock. Never through a reverse proxy, and never from a public address |
| `shareDecrypted` | optional | Plugin id → the sentence that lets that plugin be given decrypted calls (every plugin needs its own; none are allowed by default). See [Where decrypted calls go](#where-decrypted-calls-go). Config file only |
| `passwordFile` | optional | A file with the container's password on its first line (its line ending is not part of it): absolute, or relative to the config file's folder. Leave it out to type the password into Setup instead (below) |

With no `keys` section, or an empty `ekcFile`, **nothing is decrypted** and nothing else changes.
With a `passwordFile` the keys load without anyone present, when the app starts and again when
recording starts, which is what an unattended recorder needs (and Docker or Kubernetes secrets).

### Typing the password instead

Set only `ekcFile` (in Setup: **Recording → Decryption keys**) and the keys stay **locked** until you
type the container's password there and press **Unlock**. Nothing about the password is written
anywhere: it is held in memory (as the keys are) until you press **Lock** or the app quits, so
stopping and starting recording keeps it. After a restart you unlock again.

- **Only from the computer the recorder runs on.** The unlock is accepted from a browser on that
  computer, at `http://localhost:<port>`, and refused from any other address or through a reverse
  proxy: with `--bind 0.0.0.0` and no login, anyone on your network could otherwise try passwords.
  Over SSH, forward the port (`ssh -L 8080:localhost:8080 host`) and open `localhost`. Docker maps
  its connections from a gateway address, so a container uses a password file. If the interface
  is only on a network you trust, `keys.allowLanUnlock` (above) lets a private address unlock it too.
- Tries are a second apart, and a wrong password changes nothing.
- Any browser is told whether keys are held and how many; only a browser on the recorder's own
  computer is told which (cipher, key id and name, never the keys).
- Keys unlocked while recording is on are used for calls that start afterwards. **Lock** likewise
  takes effect for calls that start afterwards: a call already being decrypted finishes with the
  keys it began with (they are wiped from memory when it ends).

- **The password file must be readable by you alone** on Linux and macOS: no access for group or
  others (`600` is usual). A file others can read is refused, and the log tells you to `chmod 600`
  it. Files that really are under `/run/secrets` (Docker and Kubernetes secrets) are exempt, as the
  platform sets their mode. Windows has no mode to check: keep the file out of reach yourself.
  An editor's byte-order mark at the start of the file is ignored.
- If a file is missing, the password is wrong, or the container is damaged, the recorder **keeps
  recording with decryption off** and logs why, rather than not starting. Look for a line starting
  `Decryption is off` in the log.
- A key of the wrong size for its algorithm (a 16-byte AES-256 key, say) can never decrypt: it is
  left out, and the log names it.
- The keys are held in memory only. They are not in the config, the interface, the API, the call JSON
  or the log. The log lists how many keys loaded, and names any it couldn't use, never their bytes.
- A call is matched to a key by the **algorithm id and key id it names on the air**, as a radio does.
  A key's name and its storage location number in KFDtool are only labels. If two keysets hold the
  same id, the active one is used.

For a test with a capture, `trunk-pro replay` takes the same two files: `--ekc keys.ekc
--password-file keys.pw`. `trunk-pro tool ekc keys.ekc --password-file keys.pw` lists what a container
holds (algorithm, key id, name), to check it.

## What you get

- A decrypted call is recorded like any other, and played like one: the dashboard marks it
  **recording (decrypted)** with its cipher and key id. Its call JSON has `"encrypted": 1` (it was encrypted on
  the air), `"decrypted": 1`, and the `alg_id` and `key_id` it named. A call stays `decrypted` once
  any of it was, with the key that decrypted it, even if a later talker uses a key you don't hold. The interface's live calls carry
  `decrypted`, `algId` and `keyId`.
- A Phase 1 call joined part-way through is decrypted from its first superframe on: the receiver
  works out the call's cipher state from the next encryption sync, and the first 180 ms of such a call
  are held until it has. A Phase 2 call joined without its start learns its cipher at the end of the
  first superframe it sees (its ESS); with keys loaded the voice until then is held, so a call
  joined at a superframe's start loses nothing, and an encrypted one joined part-way through loses
  that first partial superframe (up to 360 ms; it can't be decrypted without the message
  indicator). A clear call is held the same way but its held voice is played, a little late.
- **Wrong keys give noise.** P25 voice has no check that a key is right, so a call whose key id is
  loaded with the wrong key sounds like static, as it does in a real radio.
- While keys are loaded, a call flagged encrypted is recorded from its grant (the grant doesn't say
  which key it uses). One whose key turns out not to be loaded, with no audio yet, is dropped from
  recording and followed for its link control as before. If no recorder is free when it is granted,
  it is followed as before too.
- Link control in an encrypted call may itself be encrypted. It isn't decrypted yet, so talker
  aliases and radio ids of such calls aren't read.

## Where decrypted calls go

> **Warning: uploading decrypted calls is risky.** A decrypted call is what the system's owner chose
> to encrypt. A call sent to a public service (OpenMHz, Broadcastify) can be heard by anyone, can't be
> taken back, and may be against the law or your agreement with the system's owner. A server of your
> own isn't safe by being yours: it may be reachable from outside, or pass calls on. Only allow it if
> you are sure, and authorized to share them.

So nothing is sent anywhere by default, and every plugin has to be allowed, one by one:

- **Plugins.** No plugin is given a decrypted call (its live audio and its concluded files) unless
  the config says so in that plugin's own entry. This holds for every plugin: OpenMHz, Broadcastify,
  Rdio Scanner, a stream, an upload script, one on your own network or not. There is no automatic
  exception for a plugin on your LAN.
- **To allow one**, write this sentence, exactly, in the config file (it is not in Setup on purpose):

  ```json
  "keys": {
    "ekcFile": "/etc/trunk-pro/keys.ekc",
    "shareDecrypted": { "openmhz": "I accept that decrypted calls will be sent to this plugin and may become public, and I am authorized to share them" }
  }
  ```

  Anything else in its place (`true`, `"yes"`, another sentence, or another plugin's) leaves the
  plugin withheld. Each plugin needs its own entry, under its id (`openmhz`, `broadcastify`,
  `rdioscanner`, `simplestream`, `upload-script`, ...).
- **You are told, every time.** A plugin that is withheld says so in the log (once per run: what it
  sends to, and the warning above). A plugin that is allowed logs a warning each time it starts:
  `RECEIVES DECRYPTED CALLS`, naming where it sends to (each address in its settings, marked **on
  your network** or **OUTSIDE your network**) and how to stop it. Setup's Decryption keys panel
  carries the same warning.
- **What is withheld:** the call's audio, live and concluded (WAV and M4A), and its JSON. A call no
  plugin may take is kept on disk by your call rules, as when no plugin is set up. Call and unit
  information (talkgroup, units) is not withheld: it is the same as for any encrypted call without
  keys. `trunk-pro plugin run` follows the same rules.
- **The interface.** With keys held and the interface bound to anything but `127.0.0.1`
  (`--bind 0.0.0.0`), the log warns: the interface has no login, so anyone who can reach it can
  listen to decrypted calls (the Listen page, the recordings folder it serves). Keep it on a
  network you trust, or bind it to `127.0.0.1` and forward the port.
- **On disk.** Decrypted calls are saved like any other, as WAV and JSON in the recordings folder,
  unencrypted. Treat that folder like the keys: backups and sync tools (a cloud drive, say) would
  copy them too.

## Trying it without a radio

`trunk-pro tool p25synth` makes a synthetic Phase 1 call as a capture file, encrypted under a key
from your container, and `replay` then decrypts it with the same container:

```bash
trunk-pro tool p25synth call.cu8 --algid 0x84 --kid 1235 --ekc keys.ekc --password-file keys.pw
trunk-pro replay call.cu8 --center 155150000 --rate 2400000 --p25 155200000 \
    --ekc keys.ekc --password-file keys.pw --out calls/
```

The call is a test pattern, not speech, so it shows the path works (the receiver, your keys, the
cipher, saving), not what a real system sounds like. Without `--ekc` on the `replay` the same file
writes no call. `--start ldu1` or `ldu2` joins the call part-way, and `--key <hex>` gives a key
directly (it shows in the process list: for test keys only).

`--phase2` makes a Phase 2 call instead (one logical channel of a TDMA voice channel, `--channel 0`
or `1`, scrambled for `--nac`, `--sysid` and `--wacn`). Phase 2 voice needs its system's control
channel for those numbers, so `replay` can't play it alone; `trunk-pro tool p2 call.cu8 --center 155150000 --freq 155200000 --rate 2400000 --nac …
--sysid … --wacn …` (the generator's own defaults) decodes it, and it is IQ for any other decoder to try (DSD-FME, op25) with the
same key.

