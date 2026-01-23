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

### Upcoming

- Expose exchange-layer card operations (PIN verify/unlock, random/VSD/cert/sign) via FFI ([#47](https://github.com/gematik/OpenHealth-Core/pull/47)).
- Document FFI exported APIs ([#47](https://github.com/gematik/OpenHealth-Core/pull/47)).

### 1.2.3 (Latest)

TEST

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
