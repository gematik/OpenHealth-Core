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
# UniFFI (shared primitive)
# -------------------------------------------------

# Required env:
# - `OUT_ROOT`: output root directory (cleared and re-created per invocation)
# - `CARGO_TARGET_DIR`: cargo target directory used to locate the built library
#
# Output layout (under `OUT_ROOT`):
# - `{{ language }}/`: generated sources (Kotlin or Swift)
# - `resources/<resource-id>/`: contains the built library file
#   - normalized for JNA resource lookup (e.g. `windows/x86_64` -> `win32-x86-64`)
#
# Generate UniFFI bindings and stage the built library per target.
[arg('platform', pattern='linux|windows|darwin')]
[arg('arch', pattern='x86_64|aarch64')]
[arg('language', pattern='kotlin|swift')]
[arg('library_file', pattern='(lib.+\.(so|dylib|a))|(.+\.dll)')]
[arg('profile', pattern='release|debug')]
uniffi-bindings-generate platform arch language library_file profile="release":
    #!/usr/bin/env bash
    set -euxo pipefail

    : "${OUT_ROOT:?OUT_ROOT must be set}"
    : "${CARGO_TARGET_DIR:?CARGO_TARGET_DIR must be set}"

    resource_platform="{{ platform }}"
    resource_arch="{{ arch }}"

    # Align with JNA's `Platform.RESOURCE_PREFIX` (examples: `darwin-aarch64`, `linux-x86-64`, `win32-x86-64`).
    if [ "${resource_platform}" = "windows" ]; then
        resource_platform="win32"
    fi
    if [ "${resource_arch}" = "x86_64" ]; then
        resource_arch="x86-64"
    fi

    resource_id="${resource_platform}-${resource_arch}"

    language_dir="${OUT_ROOT}/{{ language }}"
    resources_dir="${OUT_ROOT}/resources/${resource_id}"

    rm -rf "${language_dir}" "${resources_dir}"
    mkdir -p "${language_dir}" "${resources_dir}"

    cargo build \
      --manifest-path "{{ rust_manifest }}" \
      --locked \
      --profile "{{ profile }}"

    library_path="${CARGO_TARGET_DIR}/{{ profile }}/{{ library_file }}"
    test -f "${library_path}"

    cargo run \
      --manifest-path "{{ uniffi_cli }}" \
      --locked \
      --quiet \
      --bin uniffi-bindgen -- \
        generate \
        --config "{{ rust_crate }}/uniffi.toml" \
        --library "${library_path}" \
        --language "{{ language }}" \
        --out-dir "${language_dir}" \
        --no-format

    cp "${library_path}" "${resources_dir}/"

