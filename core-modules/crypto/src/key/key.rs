use zeroize::Zeroize;
use crate::utils::byte_unit::{ByteUnit, BytesExt};

#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct PrivateKey(Vec<u8>);


impl PrivateKey {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl PrivateKey {
    pub fn size(&self) -> ByteUnit {
        self.0.len().bytes()
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl PrivateKey {
    #[uniffi::constructor]
    pub fn new_from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for PrivateKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for PrivateKey {
    fn drop(&mut self) { self.0.zeroize(); }
}

pub trait KeySize {
    fn size(&self) -> ByteUnit;
}

#[derive(Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct PublicKey(Vec<u8>);

impl PublicKey {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl PublicKey {
    pub fn to_vec(&self) -> Vec<u8> {
        self.0.to_vec()
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl KeySize for PublicKey {
    fn size(&self) -> ByteUnit {
        self.0.len().bytes()
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl PublicKey {
    #[uniffi::constructor]
    pub fn new_from_bytes(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
