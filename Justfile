set shell := ["bash", "-euo", "pipefail", "-c"]

repo_root := justfile_directory()
kotlin_module := repo_root + "/core-modules-kotlin/healthcard"
rust_crate := repo_root + "/core-modules/healthcard"
uniffi_cli := repo_root + "/tools/uniffi-cli/Cargo.toml"
default_cargo_target_dir := kotlin_module + "/build/cargo"
default_out_root := kotlin_module + "/src/jvmMain"

# Generate Kotlin (JVM) UniFFI bindings and copy the native library for a target.
# Arguments:
#   resource_id: platform resource id (e.g. linux-x86-64, darwin-aarch64)
#   lib_ext: native library extension for the target (e.g. so, dylib, dll)
#   profile: cargo profile to build (default: release)
kotlin-bindings-generate resource_id lib_ext profile="release":
    #!/usr/bin/env bash
    OUT_ROOT="${OUT_ROOT:-{{default_out_root}}}"
    CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-{{default_cargo_target_dir}}}"
    CRATE="{{rust_crate}}"
    OUT_KT="${OUT_ROOT}/kotlin"
    OUT_RES="${OUT_ROOT}/resources/{{resource_id}}"

    # rm -rf "${OUT_KT}"
    mkdir -p "${OUT_KT}"
    # rm -rf "${OUT_RES}"
    mkdir -p "${OUT_RES}"

    PROFILE="{{profile}}"
    if [[ "${PROFILE}" == "release" ]]; then
    PROFILE_DIR="release"
    cargo build --manifest-path "${CRATE}/Cargo.toml" --release
    else
    PROFILE_DIR="${PROFILE}"
    cargo build --manifest-path "${CRATE}/Cargo.toml" --profile "${PROFILE}"
    fi

    LIB_PATH="${CARGO_TARGET_DIR}/${PROFILE_DIR}/libhealthcard.{{lib_ext}}"

    cargo run \
        --manifest-path "{{uniffi_cli}}" \
        --quiet \
        --bin uniffi-bindgen -- \
        generate \
        --config "${CRATE}/uniffi.toml" \
        --library "${LIB_PATH}" \
        --language kotlin \
        --out-dir "${OUT_KT}" \
        --no-format

    cp "${LIB_PATH}" "${OUT_RES}/"

# Assemble platform artifacts into a single UniFFI bundle.
# Expects downloaded artifacts under <input_root>/kotlin-bindings-<platform>/...
# and writes to <out_root>/resources/* and <out_root>/kotlin.
kotlin-bindings-assemble input_root out_root="{{repo_root}}/assembly/dist/generated/uniffi":
    #!/usr/bin/env bash
    INPUT_ROOT="{{input_root}}"
    OUT_ROOT="${OUT_ROOT:-{{out_root}}}"

    mkdir -p "${OUT_ROOT}/resources/linux-x86-64" "${OUT_ROOT}/resources/darwin-aarch64" "${OUT_ROOT}/kotlin"

    cp "${INPUT_ROOT}/kotlin-bindings-linux-x86_64/resources/linux-x86-64/libhealthcard.so" \
      "${OUT_ROOT}/resources/linux-x86-64/"
    cp "${INPUT_ROOT}/kotlin-bindings-macos-arm64/resources/darwin-aarch64/libhealthcard.dylib" \
      "${OUT_ROOT}/resources/darwin-aarch64/"
    cp -R "${INPUT_ROOT}/kotlin-bindings-linux-x86_64/kotlin/." \
      "${OUT_ROOT}/kotlin/"
