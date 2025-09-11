extern crate core;

mod ossl;
#[cfg(feature = "uniffi")]
pub mod ffi;
pub mod key;
mod utils;
pub mod cipher;
pub mod mac;
pub mod error;
// mod exchange;
// mod kem;

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();
