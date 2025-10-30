// SPDX-FileCopyrightText: Copyright 2025 gematik GmbH
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

//! OpenHealth Crypto Core
//!
//! High-level cryptographic primitives exposed with a
//! simple, ergonomic Rust API. The public surface focuses on safe wrappers for
//! common needs:
//!
//! - Symmetric encryption: `cipher::aes` (ECB, CBC, GCM)
//! - Message authentication codes: `mac` (CMAC over AES)
//! - Digests and XOFs: `digest` (SHA-2, SHA-3, BLAKE2b, SHAKE)
//! - Post-quantum KEM: `kem` (ML-KEM encapsulation/decapsulation)
//! - Key material helpers: `key`
//! - Utilities: `utils` (byte sizes, constant-time comparisons, PEM)
//!
//! Notes
//! - The internal `ossl` module contains the low-level FFI bindings and is not
//!   part of the public API.
//! - When the `uniffi` feature is enabled, `ffi` exports a UniFFI-compatible
//!   interface for use from other languages.

mod digest;
mod kem;
mod ossl;

pub mod exchange;

pub mod cipher;
pub mod error;
pub mod key;
pub mod mac;
pub mod utils;
// mod exchange;

mod ec;
#[cfg(feature = "uniffi")]
pub mod ffi;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
