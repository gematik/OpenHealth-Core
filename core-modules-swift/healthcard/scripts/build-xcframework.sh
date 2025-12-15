#!/usr/bin/env bash
#
# SPDX-FileCopyrightText: Copyright 2025 gematik GmbH
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

set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
swift_module_root="$(cd "${script_dir}/.." && pwd)"
repo_root="$(cd "${swift_module_root}/../.." && pwd)"

rust_crate="${repo_root}/core-modules/healthcard"
uniffi_cli_manifest="${repo_root}/tools/uniffi-cli/Cargo.toml"

module_name="${UNIFFI_SWIFT_MODULE_NAME:-OpenHealthHealthcard}"
ffi_module_name="${UNIFFI_SWIFT_FFI_MODULE_NAME:-OpenHealthHealthcardFFI}"

cargo_target_dir="${CARGO_TARGET_DIR:-${swift_module_root}/build/cargo}"
gen_dir="${swift_module_root}/build/generated/uniffi"
headers_dir="${swift_module_root}/build/headers"
universal_dir="${swift_module_root}/build/universal"

swift_sources_dir="${swift_module_root}/Sources/${module_name}"
swift_wrapper_dst="${swift_sources_dir}/${module_name}.swift"

xcframework_out="${swift_module_root}/${ffi_module_name}.xcframework"

mkdir -p "${gen_dir}" "${headers_dir}" "${universal_dir}" "${swift_sources_dir}"

echo "==> Building host cdylib for UniFFI metadata"
CARGO_TARGET_DIR="${cargo_target_dir}/host" cargo build --manifest-path "${rust_crate}/Cargo.toml" --release
host_lib="${cargo_target_dir}/host/release/libhealthcard.dylib"
if [[ ! -f "${host_lib}" ]]; then
  echo "Expected UniFFI metadata library at: ${host_lib}" >&2
  exit 1
fi

echo "==> Generating UniFFI Swift bindings"
rm -rf "${gen_dir}"
mkdir -p "${gen_dir}"

cargo run \
  --manifest-path "${uniffi_cli_manifest}" \
  --quiet \
  --bin uniffi-bindgen -- \
  generate \
  --config "${rust_crate}/uniffi.toml" \
  --library "${host_lib}" \
  --language swift \
  --out-dir "${gen_dir}" \
  --no-format

gen_swift="${gen_dir}/${module_name}.swift"
gen_header="${gen_dir}/${ffi_module_name}.h"
gen_modulemap="${gen_dir}/${ffi_module_name}.modulemap"

if [[ ! -f "${gen_swift}" || ! -f "${gen_header}" || ! -f "${gen_modulemap}" ]]; then
  echo "UniFFI did not generate expected outputs under: ${gen_dir}" >&2
  echo "Expected: ${gen_swift}" >&2
  echo "Expected: ${gen_header}" >&2
  echo "Expected: ${gen_modulemap}" >&2
  exit 1
fi

cp "${gen_swift}" "${swift_wrapper_dst}"
rm -rf "${headers_dir}"
mkdir -p "${headers_dir}"
cp "${gen_header}" "${headers_dir}/"
cp "${gen_modulemap}" "${headers_dir}/"

echo "==> Verifying Rust targets are installed"
required_targets=(
  aarch64-apple-ios
  aarch64-apple-ios-sim
  x86_64-apple-ios
  aarch64-apple-darwin
  x86_64-apple-darwin
)
installed_targets="$(rustup target list --installed || true)"
for t in "${required_targets[@]}"; do
  if ! echo "${installed_targets}" | grep -qx "${t}"; then
    echo "Missing Rust target: ${t}" >&2
    echo "Install it via: rustup target add ${t}" >&2
    exit 1
  fi
done

echo "==> Building Rust static libraries for Apple targets"
apple_target_dir="${cargo_target_dir}/apple"
for t in "${required_targets[@]}"; do
  CARGO_TARGET_DIR="${apple_target_dir}" cargo build --manifest-path "${rust_crate}/Cargo.toml" --release --target "${t}"
done

lib_ios_device="${apple_target_dir}/aarch64-apple-ios/release/libhealthcard.a"
lib_ios_sim_arm="${apple_target_dir}/aarch64-apple-ios-sim/release/libhealthcard.a"
lib_ios_sim_x64="${apple_target_dir}/x86_64-apple-ios/release/libhealthcard.a"
lib_macos_arm="${apple_target_dir}/aarch64-apple-darwin/release/libhealthcard.a"
lib_macos_x64="${apple_target_dir}/x86_64-apple-darwin/release/libhealthcard.a"

for f in "${lib_ios_device}" "${lib_ios_sim_arm}" "${lib_ios_sim_x64}" "${lib_macos_arm}" "${lib_macos_x64}"; do
  if [[ ! -f "${f}" ]]; then
    echo "Missing expected build output: ${f}" >&2
    exit 1
  fi
done

rm -rf "${universal_dir}"
mkdir -p "${universal_dir}/ios" "${universal_dir}/ios-simulator" "${universal_dir}/macos"

cp "${lib_ios_device}" "${universal_dir}/ios/libhealthcard.a"

lipo -create \
  "${lib_ios_sim_arm}" \
  "${lib_ios_sim_x64}" \
  -output "${universal_dir}/ios-simulator/libhealthcard.a"

lipo -create \
  "${lib_macos_arm}" \
  "${lib_macos_x64}" \
  -output "${universal_dir}/macos/libhealthcard.a"

echo "==> Creating xcframework"
rm -rf "${xcframework_out}"

xcodebuild -create-xcframework \
  -library "${universal_dir}/ios/libhealthcard.a" -headers "${headers_dir}" \
  -library "${universal_dir}/ios-simulator/libhealthcard.a" -headers "${headers_dir}" \
  -library "${universal_dir}/macos/libhealthcard.a" -headers "${headers_dir}" \
  -output "${xcframework_out}"

echo "==> Done"
echo "xcframework: ${xcframework_out}"
echo "swift wrapper: ${swift_wrapper_dst}"

