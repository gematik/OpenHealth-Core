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

# ASN.1 Swift bindings

This module provides Swift bindings for the Rust `asn1` crate via UniFFI, packaged as an Apple `xcframework`.

## Build (local)

From the repository root:

```bash
just swift-asn1-xcframework
```

Or:

```bash
just swift-xcframework asn1
```

This generates:

- `core-modules-swift/asn1/OpenHealthAsn1FFI.xcframework` (Rust static library + UniFFI C module)
- `core-modules-swift/asn1/Sources/OpenHealthAsn1/OpenHealthAsn1.swift` (UniFFI Swift wrapper)

## Notes

- `OpenHealthAsn1FFI` and `OpenHealthHealthcardFFI` are currently shipped as Rust **static** libraries.
  Linking both into the same final binary may result in duplicate-symbol linker errors (Rust std/exception symbols).
