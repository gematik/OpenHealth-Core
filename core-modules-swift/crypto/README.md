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

# Crypto Swift bindings

This module provides Swift bindings for the Rust `crypto` crate via UniFFI, packaged as an Apple `xcframework`.

## Build (local)

From the repository root:

```bash
just swift-xcframework crypto
```

This generates:

- `core-modules-swift/crypto/OpenHealthCryptoFFI.xcframework` (Rust static library + UniFFI C module)
- `core-modules-swift/crypto/Sources/OpenHealthCrypto/OpenHealthCrypto.swift` (UniFFI Swift wrapper)

## Notes

- The generated Swift wrapper and `xcframework` are ignored during development and are produced by the shared release/build pipeline.
- Building for iOS requires the Rust Apple targets to be installed (for example `aarch64-apple-ios`, `aarch64-apple-ios-sim`, and `x86_64-apple-ios`).
