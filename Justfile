set shell := ["bash", "-euo", "pipefail", "-c"]

repo_root := justfile_directory()
kotlin_module := repo_root + "/core-modules-kotlin/healthcard"
rust_crate := repo_root + "/core-modules/healthcard"
uniffi_cli := repo_root + "/tools/uniffi-cli/Cargo.toml"
default_cargo_target_dir := kotlin_module + "/build/cargo"
default_out_root := kotlin_module + "/build/generated/uniffi"
cargo_target_dir := env_var_or_default('CARGO_TARGET_DIR', default_cargo_target_dir)
bindings_out_root := env_var_or_default('OUT_ROOT', default_out_root)
bindings_kotlin_dir := bindings_out_root + "/kotlin"
bindings_resources_root := bindings_out_root + "/resources"
android_jni_root := bindings_out_root + "/android-jni"
default_assembly_input_root := repo_root + "/assembly/input"
default_assembly_out_root := repo_root + "/assembly/dist/generated/uniffi"

# Generate Kotlin (JVM) UniFFI bindings and copy the native library for a target.
# Arguments:
#   resource_id: platform resource id (e.g. linux-x86-64, darwin-aarch64)
#   profile: cargo profile to build (default: release)
#   library_file: filename of the compiled library (defaults per resource_id)
kotlin-bindings-generate resource_id profile="release" library_file="":
    rm -rf "{{bindings_kotlin_dir}}"
    mkdir -p "{{bindings_kotlin_dir}}"
    rm -rf "{{bindings_resources_root}}/{{resource_id}}"
    mkdir -p "{{bindings_resources_root}}/{{resource_id}}"

    CARGO_TARGET_DIR="{{cargo_target_dir}}" cargo build --manifest-path "{{rust_crate}}/Cargo.toml" --profile "{{profile}}"

    lib_file="{{library_file}}"; if [[ -z "${lib_file}" ]]; then case "{{resource_id}}" in linux-x86-64) lib_file="libhealthcard.so";; darwin-aarch64) lib_file="libhealthcard.dylib";; windows-x86-64) lib_file="healthcard.dll";; *) lib_file="libhealthcard.so";; esac; fi; CARGO_TARGET_DIR="{{cargo_target_dir}}" cargo run \
        --manifest-path "{{uniffi_cli}}" \
        --quiet \
        --bin uniffi-bindgen -- \
        generate \
        --config "{{rust_crate}}/uniffi.toml" \
        --library "{{cargo_target_dir}}/{{profile}}/${lib_file}" \
        --language kotlin \
        --out-dir "{{bindings_kotlin_dir}}" \
        --no-format

    lib_file="{{library_file}}"; if [[ -z "${lib_file}" ]]; then case "{{resource_id}}" in linux-x86-64) lib_file="libhealthcard.so";; darwin-aarch64) lib_file="libhealthcard.dylib";; windows-x86-64) lib_file="healthcard.dll";; *) lib_file="libhealthcard.so";; esac; fi; cp "{{cargo_target_dir}}/{{profile}}/${lib_file}" "{{bindings_resources_root}}/{{resource_id}}/"

# Assemble platform artifacts into a single UniFFI bundle.
# Expects downloaded artifacts under <input_root>/kotlin-bindings-<platform>/...
# and writes to <out_root>/resources/* and <out_root>/kotlin.
kotlin-bindings-assemble input_root=(default_assembly_input_root) out_root=(default_assembly_out_root):
    mkdir -p \
      "{{env_var_or_default('OUT_ROOT', out_root)}}/resources/linux-x86-64" \
      "{{env_var_or_default('OUT_ROOT', out_root)}}/resources/darwin-aarch64" \
      "{{env_var_or_default('OUT_ROOT', out_root)}}/resources/windows-x86-64" \
      "{{env_var_or_default('OUT_ROOT', out_root)}}/resources/android-jni" \
      "{{env_var_or_default('OUT_ROOT', out_root)}}/kotlin"

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
    OUT_ROOT="{{input_root}}/kotlin-bindings-{{resource_id}}" CARGO_TARGET_DIR="{{cargo_target_dir}}" just kotlin-bindings-generate {{resource_id}} {{profile}} {{library_file}}

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
