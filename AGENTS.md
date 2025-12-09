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

# Repository Guidelines

## Project Structure & Modules
- Rust workspace root at `./`, member crates under `core-modules/` (`asn1`, `crypto`, `crypto-openssl-sys`, `healthcard`).
- Kotlin/JVM bindings and examples live in `core-modules-kotlin/` (`healthcard`, `sample-app`).
- Documentation is in `docs/` (see `docs/architecture/README.md` and `docs/interop/jvm.md` for deeper details).

## Build, Test & Development
- Build all Rust crates: `cargo build` (from the repository root).
- Run Rust tests: `cargo test` (add `-p <crate>` to limit scope, e.g. `cargo test -p healthcard`).
- Kotlin bindings and sample: from `core-modules-kotlin/`, use `./gradlew :healthcard:build` and `./gradlew :sample-app:run`.
- Before pushing, ensure `cargo +nightly fmt` and `cargo clippy --all-targets --all-features` are clean.

## Coding Style & Naming
- Rust is formatted with `rustfmt` (see `rustfmt.toml`), 4-space indentation, max line width 120.
- Use expressive, domain-oriented names and follow existing module layout (e.g. `exchange`, `command`, `identifier` in `healthcard`).
- TODOs must reference a ticket: `// TODO OPEN-1234: Brief description`.
- New files must carry SPDX headers and license annotations consistent with existing files.

## Testing Guidelines
- Prefer Rust unit tests close to the code (inline `#[cfg(test)] mod tests`).
- For cryptography and parsing, use known-good test vectors where possible.
- JVM code uses Kotlin test/JUnit; run with `./gradlew test` (or module-specific tasks such as `:sample-app:test`).
- Aim to keep or improve test coverage for modified modules and cover edge cases relevant to healthcard flows.

## Commit & Pull Request Guidelines
- Use ticket-prefixed commit messages, e.g. `OPEN-123: Short, imperative summary`.
- Each PR should include: a short description, motivation/linked issue, and notes on testing performed.
- Call out breaking API changes and update release notes or changelogs where applicable.
- Keep PRs focused and small; follow existing patterns rather than introducing new architectural concepts without prior discussion.

## Security & Configuration
- Review `SECURITY.md` for responsible disclosure and security expectations.
- Be mindful of handling keys, secrets, and card data; never commit real credentials or production traces.
- When in doubt about crypto or card-IO changes, seek review from someone familiar with the respective module.

## Agent & AI Review Instructions
- When using AI tools for refactoring or review, follow the crate-specific templates: `core-modules/asn1/AGENTS_REVIEW_TEMPLATE.md`, `core-modules/crypto/AGENTS_REVIEW_TEMPLATE.md`, and `core-modules/healthcard/AGENTS_REVIEW_TEMPLATE.md`.
- Treat these templates as additional constraints on top of this document: keep changes incremental, behavior-preserving, and aligned with the security and architectural guidance they provide.
