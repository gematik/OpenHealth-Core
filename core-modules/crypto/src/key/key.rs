use zeroize::Zeroize;
use crate::utils::byte_unit::ByteUnit;

pub trait Key {
    fn bytes(&self) -> &[u8];
}

/// Represents a secret key in the cryptographic system.
#[derive(Clone)]
pub struct SecretKey(pub Vec<u8>);

uniffi::custom_newtype!(SecretKey, Vec<u8>);

impl SecretKey {
    pub fn length(&self) -> ByteUnit {
        ByteUnit(self.0.len())
    }
}

impl AsRef<[u8]> for SecretKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) { self.0.zeroize(); }
}