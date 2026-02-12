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
# Swift
# -------------------------------------------------

# Uses (override via env):
# - `OUT_ROOT` (default: `core-modules-swift/healthcard/build/generated/uniffi`)
# - `CARGO_TARGET_DIR` (default: `core-modules-swift/healthcard/build/cargo`)
#
# Generate Swift bindings and copy the Swift source into the Swift module.
[arg('arch', pattern='aarch64|x86_64')]
[arg('library_file', pattern='lib.+\.a')]
[arg('profile', pattern='release|debug')]
swift-bindings-generate arch="aarch64" library_file="libhealthcard.a" profile="release":
    #!/usr/bin/env bash
    set -euxo pipefail

    OUT_ROOT="{{ swift_out_root }}" \
    CARGO_TARGET_DIR="{{ swift_cargo_target_dir }}" \
      just uniffi-bindings-generate darwin "{{ arch }}" swift "{{ library_file }}" "{{ profile }}"

    gen_dir="{{ swift_out_root }}/swift"
    swift_sources_dir="{{ swift_module }}/Sources/{{ swift_module_name }}"

    mkdir -p "${swift_sources_dir}"
    cp "${gen_dir}/{{ swift_module_name }}.swift" "${swift_sources_dir}/"

# Build Apple target static libraries into `{{ swift_cargo_target_dir }}/apple` (iOS/iOS Simulator/macOS).
swift-build-apple:
    #!/usr/bin/env bash
    set -euxo pipefail

    apple_target_dir="{{ swift_cargo_target_dir }}/apple"

    for target in \
      aarch64-apple-ios \
      aarch64-apple-ios-sim \
      x86_64-apple-ios \
      aarch64-apple-darwin \
      x86_64-apple-darwin; do \
        CARGO_TARGET_DIR="${apple_target_dir}" \
          cargo build --manifest-path "{{ rust_manifest }}" --locked --release --target "$target"; \
    done

# Runs `swift-bindings-generate` and `swift-build-apple`, then packages:
# - iOS device (arm64)
# - iOS simulator (universal)
# - macOS (universal)
#
# Create an `.xcframework` for `{{ swift_ffi_module_name }}` in `core-modules-swift/healthcard/`.
swift-xcframework:
    #!/usr/bin/env bash
    set -euxo pipefail

    just swift-bindings-generate
    just swift-build-apple

    headers_dir="{{ swift_module }}/build/headers"
    rm -rf "${headers_dir}"
    mkdir -p "${headers_dir}"

    gen_dir="{{ swift_out_root }}/swift"
    cp "${gen_dir}/{{ swift_ffi_module_name }}.h" "${headers_dir}/"
    cp "${gen_dir}/{{ swift_ffi_module_name }}.modulemap" "${headers_dir}/"
    # SwiftPM expects `module.modulemap` for Clang-based binary targets inside `.xcframework` bundles.
    cp "${gen_dir}/{{ swift_ffi_module_name }}.modulemap" "${headers_dir}/module.modulemap"

    uni="{{ swift_module }}/build/universal"
    rm -rf "${uni}"
    mkdir -p "${uni}/ios" "${uni}/ios-simulator" "${uni}/macos"

    apple="{{ swift_cargo_target_dir }}/apple"

    cp "${apple}/aarch64-apple-ios/release/libhealthcard.a" "${uni}/ios/libhealthcard.a"

    lipo -create \
      "${apple}/aarch64-apple-ios-sim/release/libhealthcard.a" \
      "${apple}/x86_64-apple-ios/release/libhealthcard.a" \
      -output "${uni}/ios-simulator/libhealthcard.a"

    lipo -create \
      "${apple}/aarch64-apple-darwin/release/libhealthcard.a" \
      "${apple}/x86_64-apple-darwin/release/libhealthcard.a" \
      -output "${uni}/macos/libhealthcard.a"

    rm -rf "{{ swift_module }}/{{ swift_ffi_module_name }}.xcframework"

    xcodebuild -create-xcframework \
      -library "${uni}/ios/libhealthcard.a" -headers "${headers_dir}" \
      -library "${uni}/ios-simulator/libhealthcard.a" -headers "${headers_dir}" \
      -library "${uni}/macos/libhealthcard.a" -headers "${headers_dir}" \
      -output "{{ swift_module }}/{{ swift_ffi_module_name }}.xcframework"

