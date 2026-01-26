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

# How to Contribute to this Project

## Reporting Issues

When reporting an issue, please adhere to the following template for clarity and efficiency:
1. Bug Description: Clearly outline the problem.
2. Steps to Reproduce: Provide precise instructions to replicate the issue.
3. Optional: Include relevant code snippets.
4. OS and Architecture: Provide the version and architecture of the system where the problem occurred (e.g., Windows 11 x64, iOS 17.4.1, etc.).
5. Toolchain Details: Specify versions (e.g., Node.js, Java, etc.).
6. Library Version: Mention the version of this library involved.

## Submitting Merge Requests/Pull Requests

Ensure your Merge/Pull Request (MR/PR) includes:
1. Summary of Changes: A concise description of the updates or fixes being proposed.
2. Additional Context: Any relevant information, motivations, or dependencies that reviewers need to consider.

## Reviewing Changes (To be done by automation)

Ensure all the following pre-requirements are done:
1. Check `TODOs` are included with the provided ticket
2. Check `FIXMEs` are not included
3. Check for breaking API declaration changes:
    - Minor/Patch: All generated `.api` files must not remove or modify existing APIs
    - Major: Breaking changes must be documented in the `CHANGELOG.md`

# Repository Guidelines

## Code Style

Formatting:
```shell
cargo +nightly fmt --all
```

Linting:
```shell
cargo clippy --workspace --all-targets --all-features
```

## Test Coverage (Rust)

This project supports test coverage reporting via `cargo-llvm-cov`.

Prerequisites (per Rust toolchain):
```shell
rustup component add llvm-tools-preview
cargo install cargo-llvm-cov --locked
```

Generate reports:
```shell
cargo cov-html --workspace
cargo cov-lcov --workspace
cargo cov-json --workspace
```

Outputs:
- HTML: `target/llvm-cov-html/html/index.html`
- LCOV: `target/llvm-cov.lcov.info`
- JSON: `target/llvm-cov.json`

Optional (unstable) branch coverage:
```shell
cargo +nightly cov-json-branch --workspace
```

Output:
- Branch JSON: `target/llvm-cov.branch.json`

Optional (unstable) condition coverage for short-circuit logic:
```shell
RUSTFLAGS='-Z coverage-options=condition' cargo +nightly llvm-cov --json --output-path target/llvm-cov.condition.json --workspace --locked --all-features
```

Output:
- Condition JSON: `target/llvm-cov.condition.json`

Alternatively, use the `just` recipes:
```shell
just rust-cov-html
just rust-cov-lcov
just rust-cov-json
```

## Test Sufficiency Report (Rust)

To get a quick, combined view of *coverage vs. code complexity*, generate the quality report:
```shell
just rust-quality-report
```

The report is written to:
- `target/quality-report.md`
- `target/quality-report.json`

Notes:
- The report uses `rust-code-analysis-cli` for per-function cyclomatic complexity.
- It uses nightly branch coverage (`target/llvm-cov.branch.json`) plus stable line coverage (`target/llvm-cov.json`) to flag:
  - Uncovered branch edges in functions with `cyclomatic >= 2` (configurable via `--min-cyclo-for-branches`)
  - Uncovered single-line logic (comparisons, bitwise ops, iterator logic, short-circuit)

Prerequisites:
```shell
cargo install rust-code-analysis-cli --locked
rustup component add llvm-tools-preview --toolchain nightly-aarch64-apple-darwin
```

## Handling TODOs

**TODOs**: Always associate `TODO` comments with a ticket in the following format:

`// TODO OPEN-1234: Description of the task or acceptable workaround.`

This ensures proper tracking and management of open `TODOs`.

## License

Annotate all files with the following script:

```shell
sh tools/reuse-annotate-changed.sh
```
