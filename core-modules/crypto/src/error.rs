use crate::ossl::api::{OsslError, OsslResult};

#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum CryptoError {
    #[error("cipher finalized twice")]
    FinalizedTwice,
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("invalid ec point: {0}")]
    InvalidEcPoint(String),
    #[error("openssl error: {0}")]
    Native(String),
}

impl From<OsslError> for CryptoError {
    fn from(e: OsslError) -> Self {
        CryptoError::Native(e.to_string())
    }
}

pub type CryptoResult<T> = Result<T, CryptoError>;
