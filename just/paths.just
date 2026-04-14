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
uniffi_cli := repo_root + "/tools/uniffi-cli/Cargo.toml"

# -------------------------------------------------
# Crypto Kotlin paths
# -------------------------------------------------

crypto_rust_crate := repo_root + "/core-modules/crypto"
crypto_rust_manifest := crypto_rust_crate + "/Cargo.toml"

kotlin_crypto_module_dir := repo_root + "/core-modules-kotlin/crypto"
kotlin_crypto_out_root := kotlin_crypto_module_dir + "/build/generated/uniffi"
kotlin_crypto_cargo_target_dir := kotlin_crypto_module_dir + "/build/cargo"
android_crypto_jni_root := kotlin_crypto_out_root + "/android-jni"
