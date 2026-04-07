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

# UniFFI API (`asn1::ffi`)

This folder contains the Rust-side UniFFI surface for the `asn1` crate. The goal is to provide a small, stable,
FFI-friendly API for higher-level consumers (Kotlin/Swift) without exposing the full internal ASN.1 building blocks.

## Feature gate

The UniFFI API is only compiled when the crate feature `uniffi` is enabled.

## Exported API (initial)

### CV certificate parsing

- `parse_cv_certificate(data: Vec<u8>) -> CvCertificate`

The CV certificate is parsed from BER/DER-like TLV bytes into a structured, FFI-friendly object graph.
Exported structs should prefer accessor methods over public fields so generated bindings expose behavior through methods,
not mutable record-like field bags.

## Security notes

- Treat certificate bytes and parsed fields as potentially sensitive.
- Do not log raw inputs or parsed contents in production applications.
- Malformed inputs must be handled as recoverable errors (no panics).
