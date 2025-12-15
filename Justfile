set shell := ["bash", "-euo", "pipefail", "-c"]

repo_root := justfile_directory()
kotlin_module := repo_root + "/core-modules-kotlin/healthcard"
swift_module := repo_root + "/core-modules-swift/healthcard"
rust_crate := repo_root + "/core-modules/healthcard"
uniffi_cli := repo_root + "/tools/uniffi-cli/Cargo.toml"
swift_module_name := "OpenHealthHealthcard"
swift_ffi_module_name := "OpenHealthHealthcardFFI"

kotlin_default_cargo_target_dir := kotlin_module + "/build/cargo"
kotlin_default_out_root := kotlin_module + "/build/generated/uniffi"
swift_default_cargo_target_dir := swift_module + "/build/cargo"
swift_default_out_root := swift_module + "/build/generated/uniffi"

cargo_target_dir := env_var_or_default('CARGO_TARGET_DIR', kotlin_default_cargo_target_dir)
bindings_out_root := env_var_or_default('OUT_ROOT', kotlin_default_out_root)
android_jni_root := bindings_out_root + "/android-jni"
default_assembly_input_root := repo_root + "/assembly/input"
default_assembly_out_root := repo_root + "/assembly/dist/generated/uniffi"

# Generate UniFFI bindings and copy the built native library for a target.
# Arguments:
#   resource_id: platform resource id (e.g. linux-x86-64, darwin-aarch64)
#   language: kotlin | swift | python | ruby
#   profile: cargo profile to build (default: release)
#   library_file: filename of the compiled library (defaults per resource_id)
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
          darwin-aarch64|darwin-x86-64) lib_file="libhealthcard.dylib" ;; \
          windows-x86-64) lib_file="healthcard.dll" ;; \
          *) lib_file="libhealthcard.so" ;; \
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

# Generate Kotlin (JVM) UniFFI bindings and copy the native library for a target.
# Arguments:
#   resource_id: platform resource id (e.g. linux-x86-64, darwin-aarch64)
#   profile: cargo profile to build (default: release)
#   library_file: filename of the compiled library (defaults per resource_id)
kotlin-bindings-generate resource_id profile="release" library_file="":
    OUT_ROOT="{{env_var_or_default('OUT_ROOT', kotlin_default_out_root)}}" \
    CARGO_TARGET_DIR="{{env_var_or_default('CARGO_TARGET_DIR', kotlin_default_cargo_target_dir)}}" \
    just uniffi-bindings-generate "{{resource_id}}" kotlin "{{profile}}" "{{library_file}}"

# Assemble platform artifacts into a single UniFFI bundle.
# Expects downloaded artifacts under <input_root>/kotlin-bindings-<platform>/...
# and writes to <out_root>/resources/* and <out_root>/kotlin.
kotlin-bindings-assemble input_root=(default_assembly_input_root) out_root=(default_assembly_out_root):
    mkdir -p \
      "{{env_var_or_default('OUT_ROOT', out_root)}}/resources/linux-x86-64" \
      "{{env_var_or_default('OUT_ROOT', out_root)}}/resources/darwin-aarch64" \
      "{{env_var_or_default('OUT_ROOT', out_root)}}/resources/windows-x86-64" \
      "{{env_var_or_default('OUT_ROOT', out_root)}}/kotlin" \
      "{{env_var_or_default('OUT_ROOT', out_root)}}/android-jni"

    test -f "{{input_root}}/kotlin-bindings-linux-x86_64/resources/linux-x86-64/libhealthcard.so" \
      && cp "{{input_root}}/kotlin-bindings-linux-x86_64/resources/linux-x86-64/libhealthcard.so" "{{env_var_or_default('OUT_ROOT', out_root)}}/resources/linux-x86-64/" \
      || echo "Skipping linux-x86-64 lib: source not found"

    test -f "{{input_root}}/kotlin-bindings-macos-arm64/resources/darwin-aarch64/libhealthcard.dylib" \
      && cp "{{input_root}}/kotlin-bindings-macos-arm64/resources/darwin-aarch64/libhealthcard.dylib" "{{env_var_or_default('OUT_ROOT', out_root)}}/resources/darwin-aarch64/" \
      || echo "Skipping macos-arm64 lib: source not found"

    test -f "{{input_root}}/kotlin-bindings-windows-x86_64/resources/windows-x86-64/healthcard.dll" \
      && cp "{{input_root}}/kotlin-bindings-windows-x86_64/resources/windows-x86-64/healthcard.dll" "{{env_var_or_default('OUT_ROOT', out_root)}}/resources/windows-x86-64/" \
      || echo "Skipping windows-x86-64 lib: source not found"

    test -d "{{input_root}}/kotlin-bindings-linux-x86_64/kotlin" \
      && cp -R "{{input_root}}/kotlin-bindings-linux-x86_64/kotlin/." "{{env_var_or_default('OUT_ROOT', out_root)}}/kotlin/" \
      || echo "Skipping Kotlin sources: source directory not found"

    test -d "{{input_root}}/kotlin-bindings-linux-x86_64/android-jni" \
      && cp -r "{{input_root}}/kotlin-bindings-linux-x86_64/android-jni" "{{env_var_or_default('OUT_ROOT', out_root)}}/android-jni" \
      || echo "Skipping android libs: source not found"

# Generate bindings and place them in the layout expected by kotlin-bindings-assemble.
kotlin-bindings-generate-staged resource_id profile="release" library_file="" input_root=(default_assembly_input_root):
    raw_resource_id="{{resource_id}}"; \
    resource_id="${raw_resource_id}"; \
    staged_id="${raw_resource_id}"; \
    case "${raw_resource_id}" in \
      linux-x86-64|linux-x86_64) resource_id="linux-x86-64"; staged_id="linux-x86_64" ;; \
      darwin-aarch64|macos-arm64) resource_id="darwin-aarch64"; staged_id="macos-arm64" ;; \
      windows-x86-64|windows-x86_64) resource_id="windows-x86-64"; staged_id="windows-x86_64" ;; \
    esac; \
    OUT_ROOT="{{input_root}}/kotlin-bindings-${staged_id}}" \
    CARGO_TARGET_DIR="{{cargo_target_dir}}" \
    just kotlin-bindings-generate "${resource_id}" "{{profile}}" "{{library_file}}"

# Generate Android .so libraries for arm64-v8a and x86_64 using cargo-ndk.
# Expects ANDROID_NDK_HOME or ANDROID_NDK_ROOT to be set (e.g. via setup-ndk action in CI).
kotlin-bindings-generate-android:
    ANDROID_NDK_HOME="${ANDROID_NDK_HOME:-${ANDROID_NDK_ROOT:-}}" CARGO_TARGET_DIR="{{cargo_target_dir}}" cargo ndk \
      -t arm64-v8a -t x86_64 \
      -o "{{cargo_target_dir}}/android" \
      --manifest-path "{{rust_crate}}/Cargo.toml" \
      -- build --release

    rm -rf "{{android_jni_root}}"
    cp -r "{{cargo_target_dir}}/android" "{{android_jni_root}}"

# Publish Kotlin bindings to the local Maven repository.
kotlin-publish-local:
    cd "{{repo_root}}/core-modules-kotlin" && ./gradlew --no-daemon :healthcard:publishToMavenLocal

# Generate Swift UniFFI bindings (Swift + C header/modulemap) and copy them into the Swift package layout.
swift-bindings-generate resource_id="darwin-aarch64" profile="release" library_file="":
    OUT_ROOT="{{env_var_or_default('OUT_ROOT', swift_default_out_root)}}" \
    CARGO_TARGET_DIR="{{env_var_or_default('CARGO_TARGET_DIR', swift_default_cargo_target_dir)}}" \
    just uniffi-bindings-generate "{{resource_id}}" swift "{{profile}}" "{{library_file}}"

    out_root="{{env_var_or_default('OUT_ROOT', swift_default_out_root)}}"; \
      gen_dir="${out_root}/swift"; \
      swift_sources_dir="{{swift_module}}/Sources/{{swift_module_name}}"; \
      mkdir -p "${swift_sources_dir}"; \
      cp "${gen_dir}/{{swift_module_name}}.swift" "${swift_sources_dir}/{{swift_module_name}}.swift"

# Build Apple xcframework + Swift wrapper for the healthcard crate (UniFFI).
swift-healthcard-xcframework resource_id="darwin-aarch64":
    just swift-xcframework "{{resource_id}}"

swift-xcframework resource_id="darwin-aarch64":
    OUT_ROOT="{{env_var_or_default('OUT_ROOT', swift_default_out_root)}}" \
    CARGO_TARGET_DIR="{{env_var_or_default('CARGO_TARGET_DIR', swift_default_cargo_target_dir)}}" \
    just swift-bindings-generate "{{resource_id}}"

    just swift-check-targets

    out_root="{{env_var_or_default('OUT_ROOT', swift_default_out_root)}}"; \
      gen_dir="${out_root}/swift"; \
      headers_dir="{{swift_module}}/build/headers"; \
      rm -rf "${headers_dir}"; \
      mkdir -p "${headers_dir}"; \
      cp "${gen_dir}/{{swift_ffi_module_name}}.h" "${headers_dir}/"; \
      cp "${gen_dir}/{{swift_ffi_module_name}}.modulemap" "${headers_dir}/"

    CARGO_TARGET_DIR="{{env_var_or_default('CARGO_TARGET_DIR', swift_default_cargo_target_dir)}}/apple" cargo build --manifest-path "{{rust_crate}}/Cargo.toml" --release --target aarch64-apple-ios
    CARGO_TARGET_DIR="{{env_var_or_default('CARGO_TARGET_DIR', swift_default_cargo_target_dir)}}/apple" cargo build --manifest-path "{{rust_crate}}/Cargo.toml" --release --target aarch64-apple-ios-sim
    CARGO_TARGET_DIR="{{env_var_or_default('CARGO_TARGET_DIR', swift_default_cargo_target_dir)}}/apple" cargo build --manifest-path "{{rust_crate}}/Cargo.toml" --release --target x86_64-apple-ios
    CARGO_TARGET_DIR="{{env_var_or_default('CARGO_TARGET_DIR', swift_default_cargo_target_dir)}}/apple" cargo build --manifest-path "{{rust_crate}}/Cargo.toml" --release --target aarch64-apple-darwin
    CARGO_TARGET_DIR="{{env_var_or_default('CARGO_TARGET_DIR', swift_default_cargo_target_dir)}}/apple" cargo build --manifest-path "{{rust_crate}}/Cargo.toml" --release --target x86_64-apple-darwin

    rm -rf "{{swift_module}}/{{swift_ffi_module_name}}.xcframework"
    rm -rf "{{swift_module}}/build/universal"
    mkdir -p "{{swift_module}}/build/universal/ios" "{{swift_module}}/build/universal/ios-simulator" "{{swift_module}}/build/universal/macos"

    cp "{{env_var_or_default('CARGO_TARGET_DIR', swift_default_cargo_target_dir)}}/apple/aarch64-apple-ios/release/libhealthcard.a" "{{swift_module}}/build/universal/ios/libhealthcard.a"
    lipo -create \
      "{{env_var_or_default('CARGO_TARGET_DIR', swift_default_cargo_target_dir)}}/apple/aarch64-apple-ios-sim/release/libhealthcard.a" \
      "{{env_var_or_default('CARGO_TARGET_DIR', swift_default_cargo_target_dir)}}/apple/x86_64-apple-ios/release/libhealthcard.a" \
      -output "{{swift_module}}/build/universal/ios-simulator/libhealthcard.a"
    lipo -create \
      "{{env_var_or_default('CARGO_TARGET_DIR', swift_default_cargo_target_dir)}}/apple/aarch64-apple-darwin/release/libhealthcard.a" \
      "{{env_var_or_default('CARGO_TARGET_DIR', swift_default_cargo_target_dir)}}/apple/x86_64-apple-darwin/release/libhealthcard.a" \
      -output "{{swift_module}}/build/universal/macos/libhealthcard.a"

    xcodebuild -create-xcframework \
      -library "{{swift_module}}/build/universal/ios/libhealthcard.a" -headers "{{swift_module}}/build/headers" \
      -library "{{swift_module}}/build/universal/ios-simulator/libhealthcard.a" -headers "{{swift_module}}/build/headers" \
      -library "{{swift_module}}/build/universal/macos/libhealthcard.a" -headers "{{swift_module}}/build/headers" \
      -output "{{swift_module}}/{{swift_ffi_module_name}}.xcframework"

# Verify required Rust targets for Apple builds are installed.
swift-check-targets:
    installed_targets="$(rustup target list --installed 2>/dev/null || true)"; \
      missing=(); \
      for t in \
        aarch64-apple-ios \
        aarch64-apple-ios-sim \
        x86_64-apple-ios \
        aarch64-apple-darwin \
        x86_64-apple-darwin \
      ; do \
        if ! echo "${installed_targets}" | grep -qx "${t}"; then missing+=("${t}"); fi; \
      done; \
      if (( ${#missing[@]} > 0 )); then \
        echo "Missing Rust targets required for swift xcframework build:" >&2; \
        printf '  - %s\n' "${missing[@]}" >&2; \
        echo >&2; \
        echo "Install them via:" >&2; \
        echo "  rustup target add ${missing[*]}" >&2; \
        exit 1; \
      fi
