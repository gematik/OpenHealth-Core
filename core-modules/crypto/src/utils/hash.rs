

/// Exception thrown when an error occurs during hash operations.
#[derive(Debug)]
pub struct HashException {
    pub message: String,
    pub cause: Option<Box<dyn std::error::Error>>,
}

impl std::fmt::Display for HashException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for HashException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            Some(cause) => Some(cause.as_ref()),
            None => None,
        }
    }
}

/// Supported hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
    Shake128,
    Shake256,
}

/// Interface for cryptographic hash functions.
pub trait Hash {
    fn spec(&self) -> &HashSpec;

    /// Updates the hash computation with the given data.
    fn update(&mut self, data: &[u8]);

    /// Completes the hash computation and returns the hash value.
    fn digest(&mut self) -> Vec<u8>;
}

/// Specification for creating a hash function instance.
#[derive(Debug, Clone)]
pub struct HashSpec {
    pub algorithm: HashAlgorithm,
}

/// Creates a native hash function instance based on the given specification.
pub(crate) fn native_create_hash(_spec: &HashSpec, _scope: &CryptoScope) -> Box<dyn Hash> {
    unimplemented!()
}
