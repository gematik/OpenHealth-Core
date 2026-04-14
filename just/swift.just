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

# Usage:
# - legacy (healthcard): `just swift-bindings-generate [arch] [library_file] [profile]`
# - module-driven:      `just swift-bindings-generate <module> [arch] [library_file] [profile]`
swift-bindings-generate *ARGS:
    #!/usr/bin/env bash
    set -euxo pipefail

    set -- {{ ARGS }}

    module="healthcard"
    if [ $# -gt 0 ] && { [ "$1" = "healthcard" ] || [ "$1" = "asn1" ] || [ "$1" = "crypto" ]; }; then
        module="$1"
        shift
    fi

    arch="${1:-aarch64}"
    profile="${3:-release}"

    case "${module}" in
      healthcard)
        rust_crate_dir="{{ repo_root }}/core-modules/healthcard"
        swift_module_dir="{{ repo_root }}/core-modules-swift/healthcard"
        swift_module_name="OpenHealthHealthcard"
        swift_ffi_module_name="OpenHealthHealthcardFFI"
        built_library_file="${2:-libhealthcard.a}"
        staged_library_file="libopenhealth_healthcard.a"
        ;;
      asn1)
        rust_crate_dir="{{ repo_root }}/core-modules/asn1"
        swift_module_dir="{{ repo_root }}/core-modules-swift/asn1"
        swift_module_name="OpenHealthAsn1"
        swift_ffi_module_name="OpenHealthAsn1FFI"
        built_library_file="${2:-libasn1.a}"
        staged_library_file="libopenhealth_asn1.a"
        ;;
      crypto)
        rust_crate_dir="{{ repo_root }}/core-modules/crypto"
        swift_module_dir="{{ repo_root }}/core-modules-swift/crypto"
        swift_module_name="OpenHealthCrypto"
        swift_ffi_module_name="OpenHealthCryptoFFI"
        built_library_file="${2:-libcrypto.a}"
        staged_library_file="libopenhealth_crypto.a"
        ;;
      *)
        echo "Unknown module: ${module}" >&2
        exit 2
        ;;
    esac

    rust_manifest_path="${rust_crate_dir}/Cargo.toml"
    out_root_default="${swift_module_dir}/build/generated/uniffi"
    cargo_target_dir_default="${swift_module_dir}/build/cargo"

    OUT_ROOT="${OUT_ROOT:-${out_root_default}}" \
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${cargo_target_dir_default}}" \
      just uniffi-bindings-generate-crate darwin "${arch}" swift "${built_library_file}" "${staged_library_file}" "${rust_crate_dir}" "${rust_manifest_path}" "${profile}"

    out_root="${OUT_ROOT:-${out_root_default}}"
    gen_dir="${out_root}/swift"
    swift_sources_dir="${swift_module_dir}/Sources/${swift_module_name}"

    mkdir -p "${swift_sources_dir}"
    cp "${gen_dir}/${swift_module_name}.swift" "${swift_sources_dir}/"

# Build Apple target static libraries into `<module>/build/cargo/apple` (iOS/iOS Simulator/macOS).
swift-build-apple module="healthcard":
    #!/usr/bin/env bash
    set -euxo pipefail

    module="{{ module }}"

    case "${module}" in
      healthcard)
        rust_manifest_path="{{ repo_root }}/core-modules/healthcard/Cargo.toml"
        swift_module_dir="{{ repo_root }}/core-modules-swift/healthcard"
        ;;
      asn1)
        rust_manifest_path="{{ repo_root }}/core-modules/asn1/Cargo.toml"
        swift_module_dir="{{ repo_root }}/core-modules-swift/asn1"
        ;;
      crypto)
        rust_manifest_path="{{ repo_root }}/core-modules/crypto/Cargo.toml"
        swift_module_dir="{{ repo_root }}/core-modules-swift/crypto"
        ;;
      *)
        echo "Unknown module: ${module}" >&2
        exit 2
        ;;
    esac

    cargo_target_dir_default="${swift_module_dir}/build/cargo"
    cargo_target_dir="${CARGO_TARGET_DIR:-${cargo_target_dir_default}}"
    apple_target_dir="${cargo_target_dir}/apple"

    for target in \
      aarch64-apple-ios \
      aarch64-apple-ios-sim \
      x86_64-apple-ios \
      aarch64-apple-darwin \
      x86_64-apple-darwin; do \
        CARGO_TARGET_DIR="${apple_target_dir}" \
          cargo build --manifest-path "${rust_manifest_path}" --locked --release --features uniffi --target "$target"; \
    done

# Runs `swift-bindings-generate` and `swift-build-apple`, then packages:
# - iOS device (arm64)
# - iOS simulator (universal)
# - macOS (universal)
#
# Create an `.xcframework` for `<module>` in `core-modules-swift/<module>/`.
swift-xcframework module="healthcard":
    #!/usr/bin/env bash
    set -euxo pipefail

    module="{{ module }}"

    case "${module}" in
      healthcard)
        swift_module_dir="{{ repo_root }}/core-modules-swift/healthcard"
        swift_module_name="OpenHealthHealthcard"
        swift_ffi_module_name="OpenHealthHealthcardFFI"
        built_library_file="libhealthcard.a"
        staged_library_file="libopenhealth_healthcard.a"
        ;;
      asn1)
        swift_module_dir="{{ repo_root }}/core-modules-swift/asn1"
        swift_module_name="OpenHealthAsn1"
        swift_ffi_module_name="OpenHealthAsn1FFI"
        built_library_file="libasn1.a"
        staged_library_file="libopenhealth_asn1.a"
        ;;
      crypto)
        swift_module_dir="{{ repo_root }}/core-modules-swift/crypto"
        swift_module_name="OpenHealthCrypto"
        swift_ffi_module_name="OpenHealthCryptoFFI"
        built_library_file="libcrypto.a"
        staged_library_file="libopenhealth_crypto.a"
        ;;
      *)
        echo "Unknown module: ${module}" >&2
        exit 2
        ;;
    esac

    just swift-bindings-generate "${module}"
    just swift-build-apple "${module}"

    out_root_default="${swift_module_dir}/build/generated/uniffi"
    cargo_target_dir_default="${swift_module_dir}/build/cargo"
    out_root="${OUT_ROOT:-${out_root_default}}"
    cargo_target_dir="${CARGO_TARGET_DIR:-${cargo_target_dir_default}}"

    headers_dir="${swift_module_dir}/build/headers"
    rm -rf "${headers_dir}"
    mkdir -p "${headers_dir}"

    gen_dir="${out_root}/swift"
    cp "${gen_dir}/${swift_ffi_module_name}.h" "${headers_dir}/"
    cp "${gen_dir}/${swift_ffi_module_name}.modulemap" "${headers_dir}/"
    # SwiftPM expects `module.modulemap` for Clang-based binary targets inside `.xcframework` bundles.
    cp "${gen_dir}/${swift_ffi_module_name}.modulemap" "${headers_dir}/module.modulemap"

    uni="${swift_module_dir}/build/universal"
    rm -rf "${uni}"
    mkdir -p "${uni}/ios" "${uni}/ios-simulator" "${uni}/macos"

    apple="${cargo_target_dir}/apple"

    cp "${apple}/aarch64-apple-ios/release/${built_library_file}" "${uni}/ios/${staged_library_file}"

    lipo -create \
      "${apple}/aarch64-apple-ios-sim/release/${built_library_file}" \
      "${apple}/x86_64-apple-ios/release/${built_library_file}" \
      -output "${uni}/ios-simulator/${staged_library_file}"

    lipo -create \
      "${apple}/aarch64-apple-darwin/release/${built_library_file}" \
      "${apple}/x86_64-apple-darwin/release/${built_library_file}" \
      -output "${uni}/macos/${staged_library_file}"

    rm -rf "${swift_module_dir}/${swift_ffi_module_name}.xcframework"

    xcodebuild -create-xcframework \
      -library "${uni}/ios/${staged_library_file}" -headers "${headers_dir}" \
      -library "${uni}/ios-simulator/${staged_library_file}" -headers "${headers_dir}" \
      -library "${uni}/macos/${staged_library_file}" -headers "${headers_dir}" \
      -output "${swift_module_dir}/${swift_ffi_module_name}.xcframework"

# -------------------------------------------------
# Swift (asn1) - legacy wrappers
# -------------------------------------------------

swift-asn1-bindings-generate arch="aarch64" library_file="libopenhealth_asn1.a" profile="release":
    just swift-bindings-generate asn1 "{{ arch }}" "{{ library_file }}" "{{ profile }}"

swift-asn1-build-apple:
    just swift-build-apple asn1

swift-asn1-xcframework:
    just swift-xcframework asn1
