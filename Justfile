set shell := ["bash", "-euo", "pipefail", "-c"]

# -------------------------------------------------
# Default
# -------------------------------------------------

# List available recipes.
default:
    @just --list

# -------------------------------------------------
# Core paths
# -------------------------------------------------

repo_root := justfile_directory()

rust_crate := repo_root + "/core-modules/healthcard"
rust_manifest := rust_crate + "/Cargo.toml"
uniffi_cli := repo_root + "/tools/uniffi-cli/Cargo.toml"

# -------------------------------------------------
# Kotlin paths
# -------------------------------------------------

kotlin_module := repo_root + "/core-modules-kotlin/healthcard"
kotlin_cargo_target_dir_default := kotlin_module + "/build/cargo"
kotlin_out_root_default := kotlin_module + "/build/generated/uniffi"

kotlin_cargo_target_dir := env_var_or_default("CARGO_TARGET_DIR", kotlin_cargo_target_dir_default)
kotlin_out_root := env_var_or_default("OUT_ROOT", kotlin_out_root_default)

android_jni_root := kotlin_out_root + "/android-jni"

# -------------------------------------------------
# Swift paths
# -------------------------------------------------

swift_module := repo_root + "/core-modules-swift/healthcard"
swift_module_name := "OpenHealthHealthcard"
swift_ffi_module_name := "OpenHealthHealthcardFFI"

swift_cargo_target_dir_default := swift_module + "/build/cargo"
swift_out_root_default := swift_module + "/build/generated/uniffi"

swift_cargo_target_dir := env_var_or_default("CARGO_TARGET_DIR", swift_cargo_target_dir_default)
swift_out_root := env_var_or_default("OUT_ROOT", swift_out_root_default)

# -------------------------------------------------
# UniFFI (shared primitive)
# -------------------------------------------------

# Required env:
# - `OUT_ROOT`: output root directory (cleared and re-created per invocation)
# - `CARGO_TARGET_DIR`: cargo target directory used to locate the built library
#
# Output layout (under `OUT_ROOT`):
# - `{{ language }}/`: generated sources (Kotlin or Swift)
# - `resources/{{ platform }}-{{ arch }}/`: contains the built library file
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

    resource_id="{{ platform }}-{{ arch }}"

    language_dir="${OUT_ROOT}/{{ language }}"
    resources_dir="${OUT_ROOT}/resources/${resource_id}"

    rm -rf "${language_dir}" "${resources_dir}"
    mkdir -p "${language_dir}" "${resources_dir}"

    cargo build \
      --manifest-path "{{ rust_manifest }}" \
      --profile "{{ profile }}"

    library_path="${CARGO_TARGET_DIR}/{{ profile }}/{{ library_file }}"
    test -f "${library_path}"

    cargo run \
      --manifest-path "{{ uniffi_cli }}" \
      --quiet \
      --bin uniffi-bindgen -- \
        generate \
        --config "{{ rust_crate }}/uniffi.toml" \
        --library "${library_path}" \
        --language "{{ language }}" \
        --out-dir "${language_dir}" \
        --no-format

    cp "${library_path}" "${resources_dir}/"

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
      -- build --release

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
          cargo build --manifest-path "{{ rust_manifest }}" --release --target "$target"; \
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
