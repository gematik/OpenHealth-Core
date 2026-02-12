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

