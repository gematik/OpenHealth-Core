<!--
SPDX-FileCopyrightText: Copyright 2025 - 2026 gematik GmbH

SPDX-License-Identifier: Apache-2.0

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

*******

For additional notes and disclaimer from gematik and in case of changes by gematik,
find details in the "Readme" file.
-->

# APDU Tools (Recorder & Replay)

The APDU tools live in their own crate and provide helper types to record and replay APDU exchanges. This is useful for
debugging PACE establishment and for creating deterministic, offline test runs.

Source locations:

- Binary: `core-modules/healthcard-apdu-tools/src/bin/apdu_record.rs`
- Library helpers: `core-modules/healthcard-apdu-tools/src/apdu_tools.rs`

## Feature flag

The PC/SC transport is gated behind the `pcsc` feature on the `healthcard-apdu-tools` crate.

- Build/run tools: add `--features pcsc` to your `cargo` command.
- Use in another crate: `healthcard-apdu-tools = { path = "../core-modules/healthcard-apdu-tools", features = ["pcsc"] }`

## `apdu_record` (PC/SC recorder)

Records APDU input/output while establishing a secure channel (PACE) and writes a transcript as JSON Lines (JSONL).

Prerequisites:

- A working PC/SC stack on your system and a connected reader/card.
- If `--list-readers` shows nothing or `pcsc context establish failed`, check that the PC/SC service/daemon is running.

Show CLI help:

```sh
cargo run -p healthcard-apdu-tools --bin apdu_record --features pcsc -- --help
```

### List PC/SC readers

```sh
cargo run -p healthcard-apdu-tools --bin apdu_record --features pcsc -- --list-readers
```

### Record a transcript

```sh
cargo run -p healthcard-apdu-tools --bin apdu_record --features pcsc -- \
  --reader "<PCSC reader name>" \
  --can 123456 \
  --out ./transcript.jsonl
```

To additionally read the certificates and print them to the console:

```sh
cargo run -p healthcard-apdu-tools --bin apdu_record --features pcsc -- \
  --reader "<PCSC reader name>" \
  --can 123123 \
  --out ./transcript.jsonl \
  --read-certificates
```

Additional exchange helpers can be executed during the same secure session:

```sh
cargo run -p healthcard-apdu-tools --bin apdu_record --features pcsc -- \
  --reader "<PCSC reader name>" \
  --can 123456 \
  --out ./transcript.jsonl \
  --verify-pin 123456 \
  --change-pin 123456 654321 \
  --unlock-egk-with-puk 12345678 \
  --change-pin-with-puk 12345678 654321 \
  --sign-challenge DEADBEEF \
  --get-random 32 \
  --read-vsd
```

Notes:

- `--verify-pin` expects the home PIN (MRPIN.H).
- `--change-pin` changes the PIN using the old PIN; it expects `OLD_PIN` and `NEW_PIN`.
- `--unlock-egk-with-puk` resets the PIN retry counter using the PUK.
- `--change-pin-with-puk` resets the PIN retry counter and sets a new PIN; it expects `PUK` and `PIN` arguments.
- `--sign-challenge` expects hex-encoded input; separators such as spaces, `_`, or `:` are ignored.
- `--get-random` returns the requested number of random bytes.

APDU length options:

- Default: uses extended-length APDUs when needed.
- `--no-extended`: forces short APDUs only.

### Transcript contents (security note)

The transcript file can include sensitive values (e.g., CAN and generated ephemeral private keys used during PACE).
Treat transcripts as secrets and do not commit them to source control.

## Transcript format (JSONL)

The output is JSON Lines:

- First line: a `header` entry (`supports_extended_length`, optional `label`, optional `keys`, optional `can`)
- Following lines: `exchange` entries (`tx`/`rx` as uppercase hex) or `error` entries

## Replay in Rust (offline)

Use a recorded transcript to replay the same APDU sequence without a card/reader:

```rust
use healthcard_apdu_tools::{ReplayChannel, Transcript};
use healthcard::exchange::secure_channel::{establish_secure_channel_with, CardAccessNumber};

let transcript = Transcript::from_jsonl("transcript.jsonl")?;
let mut channel = ReplayChannel::from_transcript(transcript);
let can = CardAccessNumber::new("123456")?;
let key_generator = channel.fixed_key_generator()?.expect("transcript contains no keys");

let _secure = establish_secure_channel_with(&mut channel, &can, key_generator)?;
```

If the outgoing APDU does not match the transcript, replay fails with a mismatch error. This is intentional: it ensures
the code path and APDU sequence are identical to what was recorded.
