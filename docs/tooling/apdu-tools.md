<!--
SPDX-FileCopyrightText: Copyright 2025 gematik GmbH

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

The healthcard module contains small developer tools to record and replay APDU exchanges. This is useful for debugging
PACE establishment and for creating deterministic, offline test runs.

Source locations:

- Binary: `core-modules/healthcard/src/bin/apdu_record.rs`
- Library helpers: `core-modules/healthcard/src/exchange/apdu_tools.rs`

## Feature flag

Everything in `healthcard::exchange::apdu_tools` is gated behind the crate feature `apdu-tools`.

- Build/run tools: add `--features apdu-tools` to your `cargo` command.
- Use in another crate: `healthcard = { path = "../core-modules/healthcard", features = ["apdu-tools"] }`

## `apdu_record` (PC/SC recorder)

Records APDU input/output while establishing a secure channel (PACE) and writes a transcript as JSON Lines (JSONL).

Prerequisites:

- A working PC/SC stack on your system and a connected reader/card.
- If `--list-readers` shows nothing or `pcsc context establish failed`, check that the PC/SC service/daemon is running.

Show CLI help:

```sh
cargo run -p healthcard --bin apdu_record --features apdu-tools -- --help
```

### List PC/SC readers

```sh
cargo run -p healthcard --bin apdu_record --features apdu-tools -- --list-readers
```

### Record a transcript

```sh
cargo run -p healthcard --bin apdu_record --features apdu-tools -- \
  --reader "<PCSC reader name>" \
  --can 123456 \
  --out ./transcript.jsonl
```

To additionally read the certificates and print them to the console:

```sh
cargo run -p healthcard --bin apdu_record --features apdu-tools -- \
  --reader "<PCSC reader name>" \
  --can 123456 \
  --out ./transcript.jsonl \
  --read-certificates
```

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
use healthcard::exchange::apdu_tools::{ReplayChannel, Transcript};
use healthcard::exchange::secure_channel::{establish_secure_channel_with, CardAccessNumber};

let transcript = Transcript::from_jsonl("transcript.jsonl")?;
let mut channel = ReplayChannel::from_transcript(transcript);
let can = CardAccessNumber::new("123456")?;
let key_generator = channel.fixed_key_generator()?.expect("transcript contains no keys");

let _secure = establish_secure_channel_with(&mut channel, &can, key_generator)?;
```

If the outgoing APDU does not match the transcript, replay fails with a mismatch error. This is intentional: it ensures
the code path and APDU sequence are identical to what was recorded.
