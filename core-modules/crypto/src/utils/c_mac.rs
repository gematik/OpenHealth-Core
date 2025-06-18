use crate::key::key::SecretKey;
/// Exception thrown when an error occurs during CMAC operations.
pub struct CmacException {
    pub message: String,
    pub cause: Option<Box<dyn std::error::Error>>,
}

impl std::fmt::Debug for CmacException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::fmt::Display for CmacException {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for CmacException {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.cause {
            Some(cause) => Some(cause.as_ref()),
            None => None,
        }
    }
}

/// Enum representing the supported CMAC algorithms.
pub enum CmacAlgorithm {
    Aes,
}

/// Interface representing a CMAC (Cipher-based Message Authentication Code) instance.
pub trait Cmac {
    fn spec(&self) -> &CmacSpec;

    /// Updates the CMAC with the given data.
    fn update(&mut self, data: &[u8]);

    /// Finalizes the CMAC computation and returns the resulting MAC.
    fn final_(&mut self) -> Vec<u8>;
}

/// Specification for creating a CMAC instance.
pub struct CmacSpec {
    pub algorithm: CmacAlgorithm,
}

/// Creates a native CMAC instance based on the given specification and secret key.
pub(crate) fn native_create_cmac(
    _spec: &CmacSpec,
    _secret: &SecretKey,
) -> Box<dyn Cmac> {
    unimplemented!()
}
