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

#[cfg(feature = "uniffi")]
pub mod ffi;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
