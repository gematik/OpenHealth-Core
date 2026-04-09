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

# Release Notes

This document summarizes the publicly released versions of OpenHealth Core.

## Change Log

### 0.2.0 (Upcoming)

This release captures the changes since `0.2.0-alpha1`.

No changes documented yet.

### 0.2.0-alpha1

This release captures the changes since `0.1.1-alpha1`.

Added
- ASN.1 UniFFI bindings with dedicated Kotlin and Swift modules, including generated host/mobile packaging for `asn1` alongside `healthcard` ([#66](https://github.com/gematik/OpenHealth-Core/pull/66)).
- Additional FFI surface for healthcard exchange-layer operations such as certificate retrieval, random exchange, PACE-related flows, and PIN handling ([#47](https://github.com/gematik/OpenHealth-Core/pull/47)).
- Additional APDU command builders and ELC helper flows for healthcard operations ([#62](https://github.com/gematik/OpenHealth-Core/pull/62)).
- Zeroizing support for ASN.1 encoder buffers via the new `VecOfU8`/`ZeroizingOption` path ([#55](https://github.com/gematik/OpenHealth-Core/pull/55)).
- CodeQL analysis workflow and expanded Rust coverage quality gates ([#53](https://github.com/gematik/OpenHealth-Core/pull/53), [#57](https://github.com/gematik/OpenHealth-Core/pull/57), [#58](https://github.com/gematik/OpenHealth-Core/pull/58)).

Changed
- Kotlin binding generation and publication now use explicit module-driven `just` commands for `asn1` and `healthcard` instead of the previous variadic shell parsing ([#66](https://github.com/gematik/OpenHealth-Core/pull/66)).
- Kotlin multiplatform publication was consolidated behind the shared Gradle convention plugin, including validation of generated JVM resources and Android JNI outputs before publishing ([#66](https://github.com/gematik/OpenHealth-Core/pull/66)).
- Swift packaging and release assembly now handle both wrapper/XCFramework pairs (`OpenHealthHealthcard*` and `OpenHealthAsn1*`) consistently ([#66](https://github.com/gematik/OpenHealth-Core/pull/66)).
- Kotlin and Swift release workflows now assemble and publish both modules from one release pipeline instead of handling only the original healthcard binding flow ([#66](https://github.com/gematik/OpenHealth-Core/pull/66)).

Fixed
- PIN retry-count mapping now handles warning count `0` correctly ([#45](https://github.com/gematik/OpenHealth-Core/pull/45)).
- Maven publication coordinates for Kotlin bindings now resolve to `de.gematik.openhealth:*` again after the multiplatform build refactor ([#66](https://github.com/gematik/OpenHealth-Core/pull/66)).
- Android AAR packaging now includes the generated JNI libraries when the Android bindings are built ([#66](https://github.com/gematik/OpenHealth-Core/pull/66)).
- Swift ASN.1 tests were updated to match the current UniFFI-generated accessor style ([#66](https://github.com/gematik/OpenHealth-Core/pull/66)).
- GitHub Actions workflow dependencies and artifact handling were refreshed as part of the release/build pipeline updates ([#56](https://github.com/gematik/OpenHealth-Core/pull/56), [#65](https://github.com/gematik/OpenHealth-Core/pull/65), [#66](https://github.com/gematik/OpenHealth-Core/pull/66)).

Breaking Changes
- The legacy variadic Kotlin `just` wrappers were removed. Use explicit module-based commands such as `just kotlin-bindings-generate healthcard ...` and `just kotlin-bindings-generate-android asn1 ...` ([#66](https://github.com/gematik/OpenHealth-Core/pull/66)).

### 0.1.1-alpha1

Changed
- Updated version handling in build scripts and release workflows ([#40](https://github.com/gematik/OpenHealth-Core/pull/40)).
- Refreshed README and release-note documentation to match the current release flow ([#43](https://github.com/gematik/OpenHealth-Core/pull/43)).

### 0.0.1-alpha6
- Add missing healthcard command builders (including INTERNAL AUTHENTICATE, MSE helpers, LIST PUBLIC KEYS, GA ELC step 2).
- Add ELC epSind alle hemeral public key generation and wire it through FFI/JVM bindings.

Fixed
- JNA resource ID handling for packaged native resources ([#44](https://github.com/gematik/OpenHealth-Core/pull/44)).

### 0.0.1-alpha5

Added
- FFI bindings for healthcard ([#18](https://github.com/gematik/OpenHealth-Core/pull/18)).
- APDU tools, integration tests, and CV certificate parsing ([#36](https://github.com/gematik/OpenHealth-Core/pull/36), [#35](https://github.com/gematik/OpenHealth-Core/pull/35), [#39](https://github.com/gematik/OpenHealth-Core/pull/39)).
- Initial OpenSSL build layer and crypto/EC module updates ([#8](https://github.com/gematik/OpenHealth-Core/pull/8), [#12](https://github.com/gematik/OpenHealth-Core/pull/12)).
- CI checks, security policy, and release notes ([#13](https://github.com/gematik/OpenHealth-Core/pull/13), [#16](https://github.com/gematik/OpenHealth-Core/pull/16)).
- Swift and Kotlin binding workflows and related packaging updates ([#25](https://github.com/gematik/OpenHealth-Core/pull/25)).

Changed
- ASN.1 tag handling and EC key encoding refactor ([#10](https://github.com/gematik/OpenHealth-Core/pull/10)).
- General API refactoring across modules ([#21](https://github.com/gematik/OpenHealth-Core/pull/21)).
- Smartcard implementation refactor ([#15](https://github.com/gematik/OpenHealth-Core/pull/15)).
- Rename trusted channel to secure channel ([#23](https://github.com/gematik/OpenHealth-Core/pull/23)).
- Migration focus from KMP-first to Rust core.
- Repository packaging and release workflow adjustments (Package.swift move, Swift wrapper handling, pipeline streamlining) ([#27](https://github.com/gematik/OpenHealth-Core/pull/27), [#28](https://github.com/gematik/OpenHealth-Core/pull/28), [#26](https://github.com/gematik/OpenHealth-Core/pull/26)).

Fixed
- OpenSSL config ([#9](https://github.com/gematik/OpenHealth-Core/pull/9)).

Security
- Replace CC0 with Apache-2.0 and add REUSE headers ([#14](https://github.com/gematik/OpenHealth-Core/pull/14), [#11](https://github.com/gematik/OpenHealth-Core/pull/11)).
- Dynamic license header for generated `ossl.rs` ([#17](https://github.com/gematik/OpenHealth-Core/pull/17)).

Dependencies
- Dependabot config/allowlist and dependency bumps ([#29](https://github.com/gematik/OpenHealth-Core/pull/29), [#33](https://github.com/gematik/OpenHealth-Core/pull/33), [#31](https://github.com/gematik/OpenHealth-Core/pull/31), [#32](https://github.com/gematik/OpenHealth-Core/pull/32), [#30](https://github.com/gematik/OpenHealth-Core/pull/30)).

### 0.0.1-alpha1 –> 0.0.1-alpha4
- KMP → Rust core migration

### 0.1.2-POPP_RELEASE (June 23, 2025)

- Older version that only works with the JVM.
- Backports from main for some test related fixes.

### 0.1.1-POPP_RELEASE (June 23, 2025)

- Older version that only works with the JVM.
- Backports from main for some test related fixes.
