<!--
SPDX-FileCopyrightText: Copyright 2026 gematik GmbH

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
- build and execute command APDUs via command builders,
- parse typed card data structures from response payloads.

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

- `CommandApdu`: constructors for building command APDUs, plus `to_vec()`.
- `ResponseApdu`: object exposing `sw()`, `data()`, and `to_vec()`.
  Construct via `ResponseApdu::from_bytes(...)` or `ResponseApdu::from_parts(sw, data)`.
- `CardChannelError`: error returned by the foreign channel implementation (`Transport` vs `Apdu`).

### Command builders

Defined in `command.rs`:

- `HealthCardCommand`: constructors for the `healthcard::command` builders (SELECT, READ BINARY, MSE, GENERAL AUTHENTICATE, etc.).
- `HealthCardCommand::to_apdu(...)`: encodes to a `CommandApdu`.
- `HealthCardCommand::execute(session)`: sends the command and returns a `HealthCardResponse`.

### Stateless exchange functions

Defined in `exchange.rs` (operate on a plain `session: CardChannel`):

- `verify_pin(session, pin) -> VerifyPinResult`
- `unlock_egk_with_puk(session, puk) -> HealthCardResponseStatus`
- `change_pin(session, old_pin, new_pin) -> HealthCardResponseStatus`
- `change_pin_with_puk(session, puk, new_pin) -> HealthCardResponseStatus`
- `get_random(session, length) -> bytes`
- `read_vsd(session) -> bytes`
- `sign_challenge(session, challenge) -> bytes`
- `retrieve_certificate(session) -> bytes`
- `retrieve_certificate_from(session, certificate) -> bytes`

These helpers are useful when no secure messaging context is required.

### Typed response parsers

Defined in `parsing.rs`:

- `parse_health_card_version2(data) -> HealthCardVersion2`
- `parse_list_public_keys(data) -> ListPublicKeys`

These helpers turn raw APDU payload bytes into typed objects so foreign callers do not need local BER/TLV parsing.

### Secure channel (PACE)

Defined in `secure_channel.rs`:

- `CardAccessNumber`: CAN wrapper used during PACE establishment.
- `establish_secure_channel(session, can) -> SecureChannel`
- `SecureChannel`: stateful object that holds the secure messaging context and exposes:
  - `transmit(command) -> ResponseApdu`
  - high-level helpers (`verify_pin`, `unlock_egk_with_puk`, `change_pin`, `change_pin_with_puk`, `get_random`, `read_vsd`, `sign_challenge`, `retrieve_certificate*`)

## Security notes

- Treat `CardPin` input and all card transcripts as secrets; do not log or persist them.
- `CardPin::from_digits` zeroizes the input string after parsing, but foreign runtimes may still retain copies.
- A `ResponseApdu` may contain personal data (depending on the command); handle with care.
