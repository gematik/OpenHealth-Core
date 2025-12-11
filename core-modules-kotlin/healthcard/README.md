# SPDX-FileCopyrightText: Copyright 2025 gematik GmbH
#
# SPDX-License-Identifier: Apache-2.0
#
# *******
#
# For additional notes and disclaimer from gematik and in case of changes by gematik,
# find details in the "Readme" file.

# Healthcard Kotlin bindings (KMP)

- This module is a Kotlin Multiplatform project with a JVM target (Java-friendly via `withJava()`).
- UniFFI bindings and native libraries are expected to be provided by the shared pipeline and placed under:
  - Kotlin/Java sources: `src/jvmMain/kotlin` (and optionally `src/jvmMain/java` for wrappers).
  - Native artifacts and scaffolding: `src/jvmMain/resources/<platform-id>/`.
- Gradle no longer builds Rust or runs UniFFI; it consumes the pre-generated artifacts from the locations above.
- The `:sample-app` consumes the JVM variant of this module.

## Using `just` for bindings generation

- The repository `Justfile` provides repeatable commands for both CI and local development.
- Generate Kotlin/JVM bindings for a platform (writes to `src/jvmMain` by default):

  ```bash
  # resource_id: linux-x86-64 | darwin-aarch64 | windows-x86-64 (matches UniFFI resource id)
  just kotlin-bindings-generate darwin-aarch64
  ```

- Override output paths (e.g., to keep the working tree clean) and cargo target dir:

  ```bash
  OUT_ROOT=core-modules-kotlin/healthcard/build/generated/uniffi \
  CARGO_TARGET_DIR=core-modules-kotlin/healthcard/build/cargo \
  just kotlin-bindings-generate linux-x86-64
  ```

- On Windows, force Git Bash if `bash` resolves to WSL:

  ```bash
  CARGO_BUILD_TARGET=x86_64-pc-windows-msvc \
  just --shell "C:/Program Files/Git/bin/bash.exe" --shell-arg "-euo" --shell-arg "pipefail" --shell-arg "-c" \
  kotlin-bindings-generate windows-x86-64 healthcard.dll
  ```

- Assemble downloaded platform artifacts into a single bundle (used by CI, usable locally):

  ```bash
  # expects input like assembly/input/kotlin-bindings-linux-x86_64/...
  just kotlin-bindings-assemble assembly/input assembly/dist/generated/uniffi
  ```
