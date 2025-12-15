set shell := ["bash", "-euo", "pipefail", "-c"]

# -----------------------------
# Core paths & defaults
# -----------------------------
repo_root := justfile_directory()
rust_crate := repo_root + "/core-modules/healthcard"
uniffi_cli := repo_root + "/tools/uniffi-cli/Cargo.toml"

# Kotlin paths
kotlin_module := repo_root + "/core-modules-kotlin/healthcard"
kotlin_cargo_target_dir_default := kotlin_module + "/build/cargo"
kotlin_out_root_default := kotlin_module + "/build/generated/uniffi"
kotlin_cargo_target_dir := env_var_or_default('CARGO_TARGET_DIR', kotlin_cargo_target_dir_default)
kotlin_out_root := env_var_or_default('OUT_ROOT', kotlin_out_root_default)
android_jni_root := kotlin_out_root + "/android-jni"

# Swift paths
swift_module := repo_root + "/core-modules-swift/healthcard"
swift_module_name := "OpenHealthHealthcard"
swift_ffi_module_name := "OpenHealthHealthcardFFI"
swift_cargo_target_dir_default := swift_module + "/build/cargo"
swift_out_root_default := swift_module + "/build/generated/uniffi"
swift_cargo_target_dir := env_var_or_default('CARGO_TARGET_DIR', swift_cargo_target_dir_default)
swift_out_root := env_var_or_default('OUT_ROOT', swift_out_root_default)

# -----------------------------
# UniFFI (shared)
# -----------------------------
# Generate UniFFI bindings and copy the built native library for a target.
# resource_id controls the native library filename and resource folder (bindings are identical per arch).
[arg('resource_id', pattern='linux-x86-64|darwin-aarch64|windows-x86-64')]
uniffi-bindings-generate resource_id language profile="release" library_file="":
    test -n "${OUT_ROOT:-}" || (echo "OUT_ROOT must be set (or call a language wrapper recipe)" >&2; exit 1)
    test -n "${CARGO_TARGET_DIR:-}" || (echo "CARGO_TARGET_DIR must be set (or call a language wrapper recipe)" >&2; exit 1)

    language_dir="${OUT_ROOT}/{{language}}"; resources_dir="${OUT_ROOT}/resources/{{resource_id}}"; \
      rm -rf "${language_dir}"; mkdir -p "${language_dir}"; \
      rm -rf "${resources_dir}"; mkdir -p "${resources_dir}"

    CARGO_TARGET_DIR="${CARGO_TARGET_DIR}" cargo build --manifest-path "{{rust_crate}}/Cargo.toml" --profile "{{profile}}"

    language_dir="${OUT_ROOT}/{{language}}"; resources_dir="${OUT_ROOT}/resources/{{resource_id}}"; lib_file="{{library_file}}"; \
      if [[ -z "${lib_file}" ]]; then \
        case "{{resource_id}}" in \
          linux-x86-64) lib_file="libhealthcard.so" ;; \
          darwin-aarch64) lib_file="libhealthcard.dylib" ;; \
          windows-x86-64) lib_file="healthcard.dll" ;; \
        esac; \
      fi; \
      library_path="${CARGO_TARGET_DIR}/{{profile}}/${lib_file}"; \
      cargo run \
        --manifest-path "{{uniffi_cli}}" \
        --quiet \
        --bin uniffi-bindgen -- \
        generate \
        --config "{{rust_crate}}/uniffi.toml" \
        --library "${library_path}" \
        --language "{{language}}" \
        --out-dir "${language_dir}" \
        --no-format; \
      cp "${library_path}" "${resources_dir}/"

# -----------------------------
# Kotlin
# -----------------------------
# Generate Kotlin/JVM bindings for a platform and place native lib under OUT_ROOT/resources/<resource_id>.
kotlin-bindings-generate resource_id profile="release" library_file="":
    OUT_ROOT="{{kotlin_out_root}}" \
    CARGO_TARGET_DIR="{{kotlin_cargo_target_dir}}" \
    just uniffi-bindings-generate "{{resource_id}}" kotlin "{{profile}}" "{{library_file}}"

# Build Android .so libraries for arm64-v8a and x86_64 using cargo-ndk.
kotlin-bindings-generate-android:
    ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}" CARGO_TARGET_DIR="{{kotlin_cargo_target_dir}}" cargo ndk \
      -t arm64-v8a -t x86_64 \
      -o "{{kotlin_cargo_target_dir}}/android" \
      --manifest-path "{{rust_crate}}/Cargo.toml" \
      -- build --release

    rm -rf "{{android_jni_root}}"
    cp -r "{{kotlin_cargo_target_dir}}/android" "{{android_jni_root}}"

# Publish Kotlin bindings to the local Maven repository.
kotlin-publish-local:
    cd "{{repo_root}}/core-modules-kotlin" && ./gradlew --no-daemon :healthcard:publishToMavenLocal

# -----------------------------
# Swift
# -----------------------------
# Generate Swift bindings (Swift wrapper + C header/modulemap) into OUT_ROOT/swift and copy wrapper into the Swift package.
swift-bindings-generate resource_id="darwin-aarch64" profile="release" library_file="":
    OUT_ROOT="{{swift_out_root}}" \
    CARGO_TARGET_DIR="{{swift_cargo_target_dir}}" \
    just uniffi-bindings-generate "{{resource_id}}" swift "{{profile}}" "{{library_file}}"

    out_root="{{swift_out_root}}"; \
      gen_dir="${out_root}/swift"; \
      swift_sources_dir="{{swift_module}}/Sources/{{swift_module_name}}"; \
      mkdir -p "${swift_sources_dir}"; \
      cp "${gen_dir}/{{swift_module_name}}.swift" "${swift_sources_dir}/{{swift_module_name}}.swift"

# Build the Apple xcframework (iOS device + simulator + macOS). Assumes required Rust Apple targets are installed.
swift-xcframework resource_id="darwin-aarch64":
    OUT_ROOT="{{swift_out_root}}" \
    CARGO_TARGET_DIR="{{swift_cargo_target_dir}}" \
    just swift-bindings-generate "{{resource_id}}"

    out_root="{{swift_out_root}}"; \
      gen_dir="${out_root}/swift"; \
      headers_dir="{{swift_module}}/build/headers"; \
      rm -rf "${headers_dir}"; \
      mkdir -p "${headers_dir}"; \
      cp "${gen_dir}/{{swift_ffi_module_name}}.h" "${headers_dir}/"; \
      cp "${gen_dir}/{{swift_ffi_module_name}}.modulemap" "${headers_dir}/"

    CARGO_TARGET_DIR="{{swift_cargo_target_dir}}/apple" cargo build --manifest-path "{{rust_crate}}/Cargo.toml" --release --target aarch64-apple-ios
    CARGO_TARGET_DIR="{{swift_cargo_target_dir}}/apple" cargo build --manifest-path "{{rust_crate}}/Cargo.toml" --release --target aarch64-apple-ios-sim
    CARGO_TARGET_DIR="{{swift_cargo_target_dir}}/apple" cargo build --manifest-path "{{rust_crate}}/Cargo.toml" --release --target x86_64-apple-ios
    CARGO_TARGET_DIR="{{swift_cargo_target_dir}}/apple" cargo build --manifest-path "{{rust_crate}}/Cargo.toml" --release --target aarch64-apple-darwin
    CARGO_TARGET_DIR="{{swift_cargo_target_dir}}/apple" cargo build --manifest-path "{{rust_crate}}/Cargo.toml" --release --target x86_64-apple-darwin

    rm -rf "{{swift_module}}/{{swift_ffi_module_name}}.xcframework"
    rm -rf "{{swift_module}}/build/universal"
    mkdir -p "{{swift_module}}/build/universal/ios" "{{swift_module}}/build/universal/ios-simulator" "{{swift_module}}/build/universal/macos"

    cp "{{swift_cargo_target_dir}}/apple/aarch64-apple-ios/release/libhealthcard.a" "{{swift_module}}/build/universal/ios/libhealthcard.a"
    lipo -create \
      "{{swift_cargo_target_dir}}/apple/aarch64-apple-ios-sim/release/libhealthcard.a" \
      "{{swift_cargo_target_dir}}/apple/x86_64-apple-ios/release/libhealthcard.a" \
      -output "{{swift_module}}/build/universal/ios-simulator/libhealthcard.a"
    lipo -create \
      "{{swift_cargo_target_dir}}/apple/aarch64-apple-darwin/release/libhealthcard.a" \
      "{{swift_cargo_target_dir}}/apple/x86_64-apple-darwin/release/libhealthcard.a" \
      -output "{{swift_module}}/build/universal/macos/libhealthcard.a"

    xcodebuild -create-xcframework \
      -library "{{swift_module}}/build/universal/ios/libhealthcard.a" -headers "{{swift_module}}/build/headers" \
      -library "{{swift_module}}/build/universal/ios-simulator/libhealthcard.a" -headers "{{swift_module}}/build/headers" \
      -library "{{swift_module}}/build/universal/macos/libhealthcard.a" -headers "{{swift_module}}/build/headers" \
      -output "{{swift_module}}/{{swift_ffi_module_name}}.xcframework"

# Back-compat alias for the Swift xcframework build.
swift-healthcard-xcframework:
    just swift-xcframework
