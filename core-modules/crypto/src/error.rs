use crate::ossl::api::OsslError;

/// Errors returned by high-level cryptographic operations.
#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum CryptoError {
    /// The caller attempted to finalize a cipher twice.
    #[error("cipher finalized twice")]
    FinalizedTwice,
    /// An input or parameter was invalid, with context.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// An elliptic curve point was invalid or malformed.
    #[error("invalid ec point: {0}")]
    InvalidEcPoint(String),
    /// Underlying native cryptographic failure with original message.
    #[error("native error: {0}")]
    Native(String),
}

impl From<OsslError> for CryptoError {
    fn from(e: OsslError) -> Self {
        CryptoError::Native(e.to_string())
    }
}

/// Convenient result alias used throughout this crate.
pub type CryptoResult<T> = Result<T, CryptoError>;
