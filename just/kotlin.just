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

# Args:
# - `platform`: `linux|windows|darwin`
# - `arch`: `x86_64|aarch64`
# - `library_file`: e.g. `libhealthcard.so`, `libhealthcard.dylib`, `healthcard.dll`
# - `profile`: `release|debug`
#
# Uses (override via env):
# - `OUT_ROOT` (default: `core-modules-kotlin/healthcard/build/generated/uniffi`)
# - `CARGO_TARGET_DIR` (default: `core-modules-kotlin/healthcard/build/cargo`)
#
# Generate Kotlin bindings for a host target (Kotlin module defaults).
[arg('platform', pattern='linux|windows|darwin')]
[arg('arch', pattern='x86_64|aarch64')]
[arg('library_file')]
[arg('profile', pattern='release|debug')]
kotlin-bindings-generate platform arch library_file profile="release":
    #!/usr/bin/env bash
    set -euxo pipefail

    OUT_ROOT="{{ kotlin_out_root }}" \
    CARGO_TARGET_DIR="{{ kotlin_cargo_target_dir }}" \
    just uniffi-bindings-generate "{{ platform }}" "{{ arch }}" kotlin "{{ library_file }}" "{{ profile }}"

# Required env:
# - `ANDROID_NDK_HOME` or `ANDROID_NDK_ROOT`
#
# Build Android Rust libraries via `cargo ndk` and stage them as `android-jni/`.
kotlin-bindings-generate-android:
    #!/usr/bin/env bash
    set -euxo pipefail

    ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}"
    : "${ANDROID_NDK_HOME:?ANDROID_NDK_HOME or ANDROID_NDK_ROOT must be set}"
    export ANDROID_NDK_HOME

    cargo ndk \
      -t arm64-v8a -t x86_64 \
      -o "{{ kotlin_cargo_target_dir }}/android" \
      --manifest-path "{{ rust_manifest }}" \
      -- build --locked --release

    rm -rf "{{ android_jni_root }}"
    cp -r "{{ kotlin_cargo_target_dir }}/android" "{{ android_jni_root }}"

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
kotlin-publish-local:
    cd "{{ repo_root }}/core-modules-kotlin" \
      && ./gradlew --no-daemon :healthcard:publishToMavenLocal

