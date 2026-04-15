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
# Kotlin
# -------------------------------------------------

# Usage:
# - module-driven:      `just kotlin-bindings-generate <module> <platform> <arch> <library_file> [profile]`
[arg('module', pattern='healthcard|asn1|crypto')]
[arg('platform', pattern='linux|windows|darwin')]
[arg('arch', pattern='x86_64|aarch64')]
[arg('library_file')]
[arg('profile', pattern='release|debug')]
kotlin-bindings-generate module platform arch library_file profile="release":
    #!/usr/bin/env bash
    set -euxo pipefail

    module="{{ module }}"
    platform="{{ platform }}"
    arch="{{ arch }}"
    library_file="{{ library_file }}"
    profile="{{ profile }}"

    case "${module}" in
      healthcard)
        rust_crate_dir="{{ repo_root }}/core-modules/healthcard"
        kotlin_module_dir="{{ repo_root }}/core-modules-kotlin/healthcard"
        case "${platform}" in
          darwin)
            staged_library_file="libopenhealth_healthcard.dylib"
            ;;
          linux)
            staged_library_file="libopenhealth_healthcard.so"
            ;;
          windows)
            staged_library_file="openhealth_healthcard.dll"
            ;;
        esac
        ;;
      asn1)
        rust_crate_dir="{{ repo_root }}/core-modules/asn1"
        kotlin_module_dir="{{ repo_root }}/core-modules-kotlin/asn1"
        case "${platform}" in
          darwin)
            staged_library_file="libopenhealth_asn1.dylib"
            ;;
          linux)
            staged_library_file="libopenhealth_asn1.so"
            ;;
          windows)
            staged_library_file="openhealth_asn1.dll"
            ;;
        esac
        ;;
      crypto)
        rust_crate_dir="{{ repo_root }}/core-modules/crypto"
        kotlin_module_dir="{{ repo_root }}/core-modules-kotlin/crypto"
        case "${platform}" in
          darwin)
            staged_library_file="libopenhealth_crypto.dylib"
            ;;
          linux)
            staged_library_file="libopenhealth_crypto.so"
            ;;
          windows)
            staged_library_file="openhealth_crypto.dll"
            ;;
        esac
        ;;
      *)
        echo "Unknown module: ${module}" >&2
        exit 2
        ;;
    esac

    rust_manifest_path="${rust_crate_dir}/Cargo.toml"
    out_root_default="${kotlin_module_dir}/build/generated/uniffi"
    cargo_target_dir_default="${kotlin_module_dir}/build/cargo"

    OUT_ROOT="${OUT_ROOT:-${out_root_default}}" \
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${cargo_target_dir_default}}" \
      just uniffi-bindings-generate-crate "${platform}" "${arch}" kotlin "${library_file}" "${staged_library_file}" "${rust_crate_dir}" "${rust_manifest_path}" "${profile}"

# Generate Kotlin bindings for the `crypto` crate.
[arg('platform', pattern='linux|windows|darwin')]
[arg('arch', pattern='x86_64|aarch64')]
[arg('library_file')]
[arg('profile', pattern='release|debug')]
kotlin-bindings-generate-crypto platform arch library_file profile="release":
    #!/usr/bin/env bash
    set -euxo pipefail

    case "{{ platform }}" in
      darwin)
        staged_library_file="libopenhealth_crypto.dylib"
        ;;
      linux)
        staged_library_file="libopenhealth_crypto.so"
        ;;
      windows)
        staged_library_file="openhealth_crypto.dll"
        ;;
    esac

    OUT_ROOT="{{ kotlin_crypto_out_root }}" \
    CARGO_TARGET_DIR="{{ kotlin_crypto_cargo_target_dir }}" \
      just uniffi-bindings-generate-crate "{{ platform }}" "{{ arch }}" kotlin "{{ library_file }}" "${staged_library_file}" "{{ crypto_rust_crate }}" "{{ crypto_rust_manifest }}" "{{ profile }}"

# Required env:
# - `ANDROID_NDK_HOME` or `ANDROID_NDK_ROOT`
#
# Build Android Rust libraries via `cargo ndk` and stage them as `android-jni/`.
[arg('module', pattern='healthcard|asn1|crypto')]
[arg('profile', pattern='release|debug')]
kotlin-bindings-generate-android module="healthcard" profile="release":
    #!/usr/bin/env bash
    set -euxo pipefail

    ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
    : "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME or ANDROID_NDK_ROOT must be set}"
    export ANDROID_NDK_HOME

    module="{{ module }}"
    profile="{{ profile }}"

    case "${module}" in
      healthcard)
        rust_manifest_path="{{ repo_root }}/core-modules/healthcard/Cargo.toml"
        kotlin_module_dir="{{ repo_root }}/core-modules-kotlin/healthcard"
        android_built_library_file="libhealthcard.so"
        android_staged_library_file="libopenhealth_healthcard.so"
        ;;
      asn1)
        rust_manifest_path="{{ repo_root }}/core-modules/asn1/Cargo.toml"
        kotlin_module_dir="{{ repo_root }}/core-modules-kotlin/asn1"
        android_built_library_file="libasn1.so"
        android_staged_library_file="libopenhealth_asn1.so"
        ;;
      crypto)
        rust_manifest_path="{{ repo_root }}/core-modules/crypto/Cargo.toml"
        kotlin_module_dir="{{ repo_root }}/core-modules-kotlin/crypto"
        android_built_library_file="libcrypto.so"
        android_staged_library_file="libopenhealth_crypto.so"
        ;;
      *)
        echo "Unknown module: ${module}" >&2
        exit 2
        ;;
    esac

    out_root_default="${kotlin_module_dir}/build/generated/uniffi"
    cargo_target_dir_default="${kotlin_module_dir}/build/cargo"
    out_root="${OUT_ROOT:-${out_root_default}}"
    cargo_target_dir="${CARGO_TARGET_DIR:-${cargo_target_dir_default}}"
    android_jni_root="${out_root}/android-jni"
    cargo_profile_flag="--release"
    cargo_profile_dir="release"

    if [ "${profile}" = "debug" ]; then
        cargo_profile_flag=""
        cargo_profile_dir="debug"
    fi

    cargo ndk \
      -t arm64-v8a -t x86_64 \
      -o "${cargo_target_dir}/android" \
      --manifest-path "${rust_manifest_path}" \
      -- build --locked ${cargo_profile_flag} --features uniffi

    if [ "${cargo_profile_dir}" != "release" ]; then
        find "${cargo_target_dir}/android" -type f -path "*/release/*" | while read -r artifact; do
            debug_artifact="${artifact%/release/*}/debug/${artifact##*/}"
            if [ -f "${debug_artifact}" ]; then
                mkdir -p "$(dirname "${artifact}")"
                cp "${debug_artifact}" "${artifact}"
            fi
        done
    fi

    rm -rf "${android_jni_root}"
    cp -r "${cargo_target_dir}/android" "${android_jni_root}"

    if [ "${android_staged_library_file}" != "${android_built_library_file}" ]; then
        find "${android_jni_root}" -type f -name "${android_built_library_file}" | while read -r artifact; do
            mv "${artifact}" "$(dirname "${artifact}")/${android_staged_library_file}"
        done
    fi

# Build Android Rust libraries for the `crypto` crate and stage them as `android-jni/`.
kotlin-bindings-generate-android-crypto:
    #!/usr/bin/env bash
    set -euxo pipefail

    ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
    : "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME or ANDROID_NDK_ROOT must be set}"
    export ANDROID_NDK_HOME

    cargo ndk \
      -t arm64-v8a -t x86_64 \
      -o "{{ kotlin_crypto_cargo_target_dir }}/android" \
      --manifest-path "{{ crypto_rust_manifest }}" \
      -- build --locked --release

    rm -rf "{{ android_crypto_jni_root }}"
    cp -r "{{ kotlin_crypto_cargo_target_dir }}/android" "{{ android_crypto_jni_root }}"

    find "{{ android_crypto_jni_root }}" -type f -name 'libcrypto.so' | while read -r artifact; do
        mv "${artifact}" "$(dirname "${artifact}")/libopenhealth_crypto.so"
    done

# Useful when you generated bindings for multiple `platform/arch` pairs into separate directories and want one combined
# layout containing:
# - `resources/` (merged)
# - `kotlin/` (merged)
# - `android-jni/` (merged, if present)
#
# Merge multiple generated binding artifacts into one output directory.
kotlin-bindings-assemble input_root output_root:
    #!/usr/bin/env bash
    set -euxo pipefail

    input_root="{{ input_root }}"
    output_root="{{ output_root }}"

    : "${input_root:?Input directory is required}"
    : "${output_root:?Output directory is required}"

    rm -rf "${output_root}"
    mkdir -p "${output_root}"

    for artifact_dir in "${input_root}"/*; do
        [ -d "${artifact_dir}" ] || continue
        if [ -d "${artifact_dir}/resources" ]; then
            mkdir -p "${output_root}/resources"
            cp -a "${artifact_dir}/resources/." "${output_root}/resources/"
        fi
        if [ -d "${artifact_dir}/kotlin" ]; then
            mkdir -p "${output_root}/kotlin"
            cp -a "${artifact_dir}/kotlin/." "${output_root}/kotlin/"
        fi
        if [ -d "${artifact_dir}/android-jni" ]; then
            mkdir -p "${output_root}/android-jni"
            cp -a "${artifact_dir}/android-jni/." "${output_root}/android-jni/"
        fi
    done

# Publish the Kotlin `healthcard` module to the local Maven repository.
[arg('module', pattern='healthcard|asn1|crypto')]
kotlin-publish-local module version:
    #!/usr/bin/env bash
    set -euo pipefail

    cd "{{ repo_root }}/core-modules-kotlin"

    ORG_GRADLE_PROJECT_version="{{ version }}" \
      ./gradlew --no-daemon :{{ module }}:publishToMavenLocal
