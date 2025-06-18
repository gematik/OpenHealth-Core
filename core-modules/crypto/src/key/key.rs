use crate::utils::byte_unit::ByteUnit;

pub trait Key {
    fn data(&self) -> &[u8];
}

/// Represents a secret key in the cryptographic system.
#[derive(Clone)]
pub struct SecretKey {
    pub data: Vec<u8>,
    pub length: ByteUnit,
}

impl SecretKey {
    pub fn new(data: Vec<u8>) -> Self {
        let length = ByteUnit(data.len());
        Self { data, length }
    }
}

impl Key for SecretKey {
    fn data(&self) -> &[u8] {
        &self.data
    }
}

impl PartialEq for SecretKey {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data && self.length == other.length
    }
}

impl Eq for SecretKey {}

impl std::hash::Hash for SecretKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.data.hash(state);
        self.length.hash(state);
    }
}

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretKey(data={:?})", self.data)
    }
}

impl std::fmt::Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretKey(data={:?})", self.data)
    }
}