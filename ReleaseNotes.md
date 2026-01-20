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

# Release Notes

This document summarizes the publicly released versions of OpenHealth Core.

## Change Log

### 0.0.1-alpha5 (Latest)

Added
- FFI bindings for healthcard (OPEN-86).
- APDU tools, integration tests, and CV certificate parsing (OPEN-94, OPEN-97, OPEN-99).
- Initial OpenSSL build layer and crypto/EC module updates (OPEN-66, OPEN-64).
- CI checks, security policy, and release notes (OPEN-81, OPEN-84).
- Swift and Kotlin binding workflows and related packaging updates (OPEN-87).

Changed
- ASN.1 tag handling and EC key encoding refactor.
- General API refactoring across modules (OPEN-85).
- Smartcard implementation refactor (OPEN-63).
- Rename trusted channel to secure channel (OPEN-93).
- Migration focus from KMP-first to Rust core.
- Repository packaging and release workflow adjustments (Package.swift move, Swift wrapper handling, pipeline streamlining).

Fixed
- OpenSSL config (OPEN-71).

Security
- Replace CC0 with Apache-2.0 and add REUSE headers (OPEN-82, OPEN-76).
- Dynamic license header for generated `ossl.rs`.

Dependencies
- Dependabot config/allowlist and dependency bumps (OPEN-96, dependabot updates).

### 0.0.1-alpha1–0.0.1-alpha4
- KMP → Rust core migration

### 0.1.2-POPP_RELEASE (June 23, 2025)

- Older version that only works with the JVM.
- Backports from main for some test related fixes.

### 0.1.1-POPP_RELEASE (June 23, 2025)

- Older version that only works with the JVM.
- Backports from main for some test related fixes.
