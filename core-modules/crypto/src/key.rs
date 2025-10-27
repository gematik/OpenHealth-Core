use crate::utils::byte_unit::{ByteUnit, BytesExt};
use core::marker::PhantomData;
use zeroize::Zeroizing;

pub trait Role {}
pub struct Private;
impl Role for Private {}
pub struct Public;
impl Role for Public {}

pub struct KeyMaterial<R: Role, Z: AsRef<[u8]>> {
    bytes: Z,
    _role: PhantomData<R>,
}

impl<R: Role, Z: AsRef<[u8]>> KeyMaterial<R, Z> {
    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }

    pub fn size(&self) -> ByteUnit {
        self.bytes.as_ref().len().bytes()
    }

    pub fn len(&self) -> usize {
        self.bytes.as_ref().len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.as_ref().is_empty()
    }
}

impl<R: Role> KeyMaterial<R, Vec<u8>> {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        KeyMaterial { _role: PhantomData, bytes: bytes.into() }
    }

    pub fn to_vec(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl<R: Role> KeyMaterial<R, Zeroizing<Vec<u8>>> {
    pub fn new_secret(bytes: impl Into<Vec<u8>>) -> Self {
        KeyMaterial { _role: PhantomData, bytes: Zeroizing::new(bytes.into()) }
    }
}

impl<R: Role, Z: AsRef<[u8]>> AsRef<[u8]> for KeyMaterial<R, Z> {
    fn as_ref(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}

pub type PrivateKey = KeyMaterial<Private, Zeroizing<Vec<u8>>>;
pub type PublicKey = KeyMaterial<Public, Vec<u8>>;

impl<R: Role> std::fmt::Debug for KeyMaterial<R, Zeroizing<Vec<u8>>> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("role", &std::any::type_name::<R>())
            .field("size", &self.size())
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for KeyMaterial<Public, Vec<u8>> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("role", &"Public")
            .field("size", &self.size())
            .field("bytes", &format!("0x{}", hex::encode(&self.bytes)))
            .finish()
    }
}
