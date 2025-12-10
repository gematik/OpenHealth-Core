set shell := ["bash", "-euo", "pipefail", "-c"]

repo_root := justfile_directory()
kotlin_module := repo_root + "/core-modules-kotlin/healthcard"
rust_crate := repo_root + "/core-modules/healthcard"
uniffi_cli := repo_root + "/tools/uniffi-cli/Cargo.toml"
default_cargo_target_dir := kotlin_module + "/build/cargo"
default_out_root := kotlin_module + "/src/jvmMain"
cargo_target_dir := env_var_or_default('CARGO_TARGET_DIR', default_cargo_target_dir)
bindings_out_root := env_var_or_default('OUT_ROOT', default_out_root)
bindings_kotlin_dir := bindings_out_root + "/kotlin"
bindings_resources_root := bindings_out_root + "/resources"
default_assembly_out_root := repo_root + "/assembly/dist/generated/uniffi"

# Generate Kotlin (JVM) UniFFI bindings and copy the native library for a target.
# Arguments:
#   resource_id: platform resource id (e.g. linux-x86-64, darwin-aarch64)
#   lib_ext: native library extension for the target (e.g. so, dylib, dll)
#   profile: cargo profile to build (default: release)
kotlin-bindings-generate resource_id lib_ext profile="release":
    rm -rf "{{bindings_kotlin_dir}}"
    mkdir -p "{{bindings_kotlin_dir}}"
    rm -rf "{{bindings_resources_root}}/{{resource_id}}"
    mkdir -p "{{bindings_resources_root}}/{{resource_id}}"

    CARGO_TARGET_DIR="{{cargo_target_dir}}" cargo build --manifest-path "{{rust_crate}}/Cargo.toml" --profile "{{profile}}"

    CARGO_TARGET_DIR="{{cargo_target_dir}}" cargo run \
        --manifest-path "{{uniffi_cli}}" \
        --quiet \
        --bin uniffi-bindgen -- \
        generate \
        --config "{{rust_crate}}/uniffi.toml" \
        --library "{{cargo_target_dir}}/{{profile}}/libhealthcard.{{lib_ext}}" \
        --language kotlin \
        --out-dir "{{bindings_kotlin_dir}}" \
        --no-format

    cp "{{cargo_target_dir}}/{{profile}}/libhealthcard.{{lib_ext}}" "{{bindings_resources_root}}/{{resource_id}}/"

# Assemble platform artifacts into a single UniFFI bundle.
# Expects downloaded artifacts under <input_root>/kotlin-bindings-<platform>/...
# and writes to <out_root>/resources/* and <out_root>/kotlin.
kotlin-bindings-assemble input_root out_root="{{default_assembly_out_root}}":
    mkdir -p "{{env_var_or_default('OUT_ROOT', out_root)}}/resources/linux-x86-64" "{{env_var_or_default('OUT_ROOT', out_root)}}/resources/darwin-aarch64" "{{env_var_or_default('OUT_ROOT', out_root)}}/kotlin"

    cp "{{input_root}}/kotlin-bindings-linux-x86_64/resources/linux-x86-64/libhealthcard.so" \
      "{{env_var_or_default('OUT_ROOT', out_root)}}/resources/linux-x86-64/"
    cp "{{input_root}}/kotlin-bindings-macos-arm64/resources/darwin-aarch64/libhealthcard.dylib" \
      "{{env_var_or_default('OUT_ROOT', out_root)}}/resources/darwin-aarch64/"
    cp -R "{{input_root}}/kotlin-bindings-linux-x86_64/kotlin/." \
      "{{env_var_or_default('OUT_ROOT', out_root)}}/kotlin/"
