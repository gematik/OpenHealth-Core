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

# UniFFI API (`healthcard::ffi`)

This folder contains the Rust-side UniFFI surface for the `healthcard` crate. The goal is to provide an FFI-friendly API
to:

- send/receive raw APDUs,
- run high-level exchange operations (PIN verify, certificate retrieval, etc.),
- establish and use a secure channel (PACE).

## Feature gate

The UniFFI API is only compiled when the crate feature `uniffi` is enabled.

## Core concepts

### `CardChannel` (foreign interface)

Foreign code implements `CardChannel` and passes it into exported functions and objects as `session`.

- `supports_extended_length() -> bool`
- `transmit(command: CommandApdu) -> ResponseApdu`

Internally, calls to the foreign `transmit` implementation are serialized to provide the core library with `&mut`
semantics.

### Raw APDU types

Defined in `channel.rs`:

- `CommandApdu`: constructors for building command APDUs, plus `to_bytes()`.
- `ResponseApdu`: record containing `sw` (SW1SW2), `status` (interpreted), and `data` (response data).
- `CardChannelError`: error returned by the foreign channel implementation (`Transport` vs `Apdu`).

### Stateless exchange functions

Defined in `exchange.rs` (operate on a plain `session: CardChannel`):

- `verify_pin(session, pin) -> VerifyPinResult`
- `unlock_egk(session, method, puk, old_secret, new_secret) -> HealthCardResponseStatus`
- `get_random(session, length) -> bytes`
- `read_vsd(session) -> bytes`
- `sign_challenge(session, challenge) -> bytes`
- `retrieve_certificate(session) -> bytes`
- `retrieve_certificate_from(session, certificate) -> bytes`

These helpers are useful when no secure messaging context is required.

### Secure channel (PACE)

Defined in `secure_channel.rs`:

- `CardAccessNumber`: CAN wrapper used during PACE establishment.
- `establish_secure_channel(session, can) -> SecureChannel`
- `SecureChannel`: stateful object that holds the secure messaging context and exposes:
  - `transmit(command) -> ResponseApdu`
  - high-level helpers (`verify_pin`, `unlock_egk`, `get_random`, `read_vsd`, `sign_challenge`, `retrieve_certificate*`)

## Security notes

- Treat `CardPin` input and all card transcripts as secrets; do not log or persist them.
- `CardPin::from_digits` zeroizes the input string after parsing, but foreign runtimes may still retain copies.
- A `ResponseApdu` may contain personal data (depending on the command); handle with care.

