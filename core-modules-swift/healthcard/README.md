<!--
SPDX-FileCopyrightText: Copyright 2025 gematik GmbH

SPDX-License-Identifier: Apache-2.0

*******

For additional notes and disclaimer from gematik and in case of changes by gematik,
find details in the "Readme" file.
-->

# Healthcard Swift bindings

This module provides Swift bindings for the Rust `healthcard` crate via UniFFI, packaged as an Apple `xcframework`.

## Build (local)

From the repository root:

```bash
just swift-healthcard-xcframework
```

This generates:

- `core-modules-swift/healthcard/OpenHealthHealthcardFFI.xcframework` (Rust static library + UniFFI C module)
- `core-modules-swift/healthcard/Sources/OpenHealthHealthcard/OpenHealthHealthcard.swift` (UniFFI Swift wrapper)

## Use

After building, you can consume this as a Swift Package via:

- `core-modules-swift/healthcard/Package.swift`

Notes:

- Building for iOS requires the Rust targets to be installed (e.g. `aarch64-apple-ios`, `aarch64-apple-ios-sim`, `x86_64-apple-ios`).
- The `just` recipes do not auto-install missing targets.
- For OpenSSL build troubleshooting, set `OPENSSL_SYS_PRINT_LOG_PATHS=1` to print the per-target `configure.log` location during builds.
