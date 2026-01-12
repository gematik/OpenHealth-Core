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

# Healthcard Swift bindings

This module provides Swift bindings for the Rust `healthcard` crate via UniFFI, packaged as an Apple `xcframework`.

## Build (local)

From the repository root:

```bash
just swift-xcframework
```

This generates:

- `core-modules-swift/healthcard/OpenHealthHealthcardFFI.xcframework` (Rust static library + UniFFI C module)
- `core-modules-swift/healthcard/Sources/OpenHealthHealthcard/OpenHealthHealthcard.swift` (UniFFI Swift wrapper)

## Use

After building, you can consume this as a Swift Package via:

- the repository root `Package.swift`

Notes:

- Building for iOS requires the Rust targets to be installed (e.g. `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`).
- The `just` recipes do not auto-install missing targets.
- For OpenSSL build troubleshooting, set `OPENSSL_SYS_PRINT_LOG_PATHS=1` to print the per-target `configure.log` location during builds.
