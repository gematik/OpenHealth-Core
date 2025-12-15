set shell := ["bash", "-euo", "pipefail", "-c"]

# -------------------------------------------------
# Default
# -------------------------------------------------

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

[arg('platform', pattern='linux|windows|darwin')]
[arg('arch', pattern='x86_64|aarch64')]
[arg('language', pattern='kotlin|swift')]
[arg('library_file', pattern='(lib.+\.(so|dylib|a))|(.+\.dll)')]
[arg('profile', pattern='release|debug')]
uniffi-bindings-generate platform arch language library_file profile="release":
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

[arg('platform', pattern='linux|windows|darwin')]
[arg('arch', pattern='x86_64|aarch64')]
[arg('library_file', pattern='lib.+\.so|.+\.dll|lib.+\.dylib')]
[arg('profile', pattern='release|debug')]
kotlin-bindings-generate platform arch library_file profile="release":
    OUT_ROOT="{{ kotlin_out_root }}" \
    CARGO_TARGET_DIR="{{ kotlin_cargo_target_dir }}" \
      just uniffi-bindings-generate "{{ platform }}" "{{ arch }}" kotlin "{{ library_file }}" "{{ profile }}"

kotlin-bindings-generate-android:
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

kotlin-publish-local:
    cd "{{ repo_root }}/core-modules-kotlin" \
      && ./gradlew --no-daemon :healthcard:publishToMavenLocal

# -------------------------------------------------
# Swift
# -------------------------------------------------

[arg('arch', pattern='aarch64|x86_64')]
[arg('library_file', pattern='lib.+\.a')]
[arg('profile', pattern='release|debug')]
swift-bindings-generate arch="aarch64" library_file="libhealthcard.a" profile="release":
    OUT_ROOT="{{ swift_out_root }}" \
    CARGO_TARGET_DIR="{{ swift_cargo_target_dir }}" \
      just uniffi-bindings-generate darwin "{{ arch }}" swift "{{ library_file }}" "{{ profile }}"

    gen_dir="{{ swift_out_root }}/swift"
    swift_sources_dir="{{ swift_module }}/Sources/{{ swift_module_name }}"

    mkdir -p "${swift_sources_dir}"
    cp "${gen_dir}/{{ swift_module_name }}.swift" "${swift_sources_dir}/"

swift-build-apple:
    apple_target_dir="{{ swift_cargo_target_dir }}/apple"

    for target in \
      aarch64-apple-ios \
      aarch64-apple-ios-sim \
      x86_64-apple-ios \
      aarch64-apple-darwin \
      x86_64-apple-darwin; do \
        CARGO_TARGET_DIR="${apple_target_dir}" \
          cargo build --manifest-path "{{ rust_manifest }}" --release --target "$$target"; \
    done

swift-xcframework:
    just swift-bindings-generate
    just swift-build-apple

    headers_dir="{{ swift_module }}/build/headers"
    rm -rf "${headers_dir}"
    mkdir -p "${headers_dir}"

    gen_dir="{{ swift_out_root }}/swift"
    cp "${gen_dir}/{{ swift_ffi_module_name }}.h" "${headers_dir}/"
    cp "${gen_dir}/{{ swift_ffi_module_name }}.modulemap" "${headers_dir}/"

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

swift-healthcard-xcframework:
    just swift-xcframework