extern crate core;

mod ossl;
pub mod key;
pub mod utils;
pub mod cipher;
pub mod mac;
pub mod error;
// mod exchange;
// mod kem;

#[cfg(feature = "uniffi")]
pub mod ffi;
mod digest;
mod kem;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
