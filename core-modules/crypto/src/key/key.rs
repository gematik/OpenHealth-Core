use zeroize::Zeroize;
use crate::utils::byte_unit::ByteUnit;

pub trait Key {
    fn bytes(&self) -> &[u8];
}

#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct SecretKey(Vec<u8>);

impl SecretKey {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
    
    pub fn size(&self) -> ByteUnit {
        ByteUnit(self.0.len() as u64)
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