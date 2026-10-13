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

**Phase 2 is newer than Phase 1 and less checked.** Phase 1 is verified against the standard
(TIA-102.AAAD) and against captures from real radios. The standard's text for Phase 2 voice
(TIA-102.AAAD-B) isn't public; the layout used here (18 voice frames of 7 keystream octets in each
superframe, the MI in the MAC_PTT and each superframe's ESS) is the one op25 and DSD-FME agree on,
and it is tested against a separate implementation of the same layout, not against a capture from
a Phase 2 system. If your Phase 2 call decrypts to noise with the right key, tell us (with the
algorithm and a capture if you can).

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
| `passwordFile` | to decrypt | A file with the container's password on its first line (its line ending is not part of it): absolute, or relative to the config file's folder |

With no `keys` section, or an empty `ekcFile`, **nothing is decrypted** and nothing else changes.
Both files are read when recording starts, so changes apply the next time you start it.

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

- A decrypted call is recorded like any other. Its call JSON has `"encrypted": 1` (it was encrypted on
  the air), `"decrypted": 1`, and the `alg_id` and `key_id` it named. A call stays `decrypted` once
  any of it was, with the key that decrypted it, even if a later talker uses a key you don't hold. The interface's live calls carry
  `decrypted`, `algId` and `keyId`.
- A Phase 1 call joined part-way through is decrypted from its first superframe on: the receiver
  works out the call's cipher state from the next encryption sync, and the first 180 ms of such a call
  are held until it has. A Phase 2 call joined part-way through (without its start) is decrypted from
  the first superframe's last burst on, up to 360 ms in.
- **Wrong keys give noise.** P25 voice has no check that a key is right, so a call whose key id is
  loaded with the wrong key sounds like static, as it does in a real radio.
- While keys are loaded, a call flagged encrypted is recorded from its grant (the grant doesn't say
  which key it uses). One whose key turns out not to be loaded, with no audio yet, is dropped from
  recording and followed for its link control as before. If no recorder is free when it is granted,
  it is followed as before too.
- Link control in an encrypted call may itself be encrypted. It isn't decrypted yet, so talker
  aliases and radio ids of such calls aren't read.
