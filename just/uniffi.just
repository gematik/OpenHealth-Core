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

    rust_crate_dir="{{ repo_root }}/core-modules/healthcard"
    rust_manifest_path="${rust_crate_dir}/Cargo.toml"
    just uniffi-bindings-generate-crate "{{ platform }}" "{{ arch }}" "{{ language }}" "{{ library_file }}" "${rust_crate_dir}" "${rust_manifest_path}" "{{ profile }}"

# Generate UniFFI bindings and stage the built library for an explicit crate/manifest.
[arg('platform', pattern='linux|windows|darwin')]
[arg('arch', pattern='x86_64|aarch64')]
[arg('language', pattern='kotlin|swift')]
[arg('library_file', pattern='(lib.+\.(so|dylib|a))|(.+\.dll)')]
[arg('rust_crate_dir')]
[arg('rust_manifest_path')]
[arg('profile', pattern='release|debug')]
uniffi-bindings-generate-crate platform arch language library_file rust_crate_dir rust_manifest_path profile="release":
    #!/usr/bin/env bash
    set -euxo pipefail

    : "${OUT_ROOT:?OUT_ROOT must be set}"
    : "${CARGO_TARGET_DIR:?CARGO_TARGET_DIR must be set}"

    profile="{{ profile }}"
    cargo_profile_dir="release"

    if [ "${profile}" = "debug" ]; then
        cargo_profile_dir="debug"
    fi

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

    if [ "${profile}" = "debug" ]; then
        cargo build \
          --manifest-path "{{ rust_manifest_path }}" \
          --locked \
          --features uniffi
    else
        cargo build \
          --manifest-path "{{ rust_manifest_path }}" \
          --locked \
          --profile release \
          --features uniffi
    fi

    requested_library_file="{{ library_file }}"
    library_path="${CARGO_TARGET_DIR}/${cargo_profile_dir}/${requested_library_file}"

    if [ ! -f "${library_path}" ]; then
        fallback_library_file="${requested_library_file/openhealth_/}"
        fallback_library_path="${CARGO_TARGET_DIR}/${cargo_profile_dir}/${fallback_library_file}"
        test -f "${fallback_library_path}"
        library_path="${fallback_library_path}"
    fi

    cargo run \
      --manifest-path "{{ uniffi_cli }}" \
      --locked \
      --quiet \
      --bin uniffi-bindgen -- \
        generate \
        --config "{{ rust_crate_dir }}/uniffi.toml" \
        --library "${library_path}" \
        --language "{{ language }}" \
        --out-dir "${language_dir}" \
        --no-format

    cp "${library_path}" "${resources_dir}/${requested_library_file}"
