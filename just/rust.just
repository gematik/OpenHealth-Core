#
# SPDX-FileCopyrightText: Copyright 2026 gematik GmbH
#
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# *******
#
# For additional notes and disclaimer from gematik and in case of changes by gematik,
# find details in the "Readme" file.

# -------------------------------------------------
# Rust (workspace)
# -------------------------------------------------

# Generate a Rust coverage report (requires `cargo-llvm-cov`).
rust-cov *ARGS="":
    #!/usr/bin/env bash
    set -euo pipefail
    cargo llvm-cov --workspace --locked --all-features {{ ARGS }}

# Generate an HTML report under `target/llvm-cov-html/` (requires `cargo-llvm-cov`).
rust-cov-html *ARGS="":
    #!/usr/bin/env bash
    set -euo pipefail
    cargo llvm-cov --workspace --locked --all-features --html --output-dir target/llvm-cov-html {{ ARGS }}

# Generate an LCOV report at `target/llvm-cov.lcov.info` (requires `cargo-llvm-cov`).
rust-cov-lcov *ARGS="":
    #!/usr/bin/env bash
    set -euo pipefail
    cargo llvm-cov --workspace --locked --all-features --lcov --output-path target/llvm-cov.lcov.info {{ ARGS }}

# Generate a JSON report at `target/llvm-cov.json` (requires `cargo-llvm-cov`).
rust-cov-json *ARGS="":
    #!/usr/bin/env bash
    set -euo pipefail
    cargo llvm-cov --workspace --locked --all-features --json --output-path target/llvm-cov.json {{ ARGS }}

# Generate a nightly branch coverage JSON at `target/llvm-cov.branch.json` (requires `cargo-llvm-cov` + nightly + llvm-tools-preview).
rust-cov-json-branch *ARGS="":
    #!/usr/bin/env bash
    set -euo pipefail
    cargo +nightly llvm-cov --workspace --locked --all-features --json --branch --output-path target/llvm-cov.branch.json {{ ARGS }}

# Combine coverage (llvm-cov JSON) with static complexity metrics.
# Outputs:
# - `target/quality-report.md`
# - `target/quality-report.json`
rust-quality-report *ARGS="":
    # Run tests once and then generate multiple report formats from the same profile data.
    cargo +nightly llvm-cov clean --workspace
    cargo +nightly llvm-cov --workspace --locked --all-features --no-report
    cargo +nightly llvm-cov report --json --output-path target/llvm-cov.json
    cargo +nightly llvm-cov report --branch --json --output-path target/llvm-cov.branch.json
    cargo +nightly llvm-cov report --html --output-dir target/llvm-cov-html
    python3 "{{ repo_root }}/tools/quality-report.py" --ignore-file "{{ repo_root }}/tools/quality-report-ignore.txt" {{ ARGS }}

# Clean instrumented artifacts created by `cargo llvm-cov`.
rust-cov-clean:
    cargo llvm-cov clean --workspace

