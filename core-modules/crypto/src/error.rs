use crate::ossl::api::{OsslError, OsslResult};

#[derive(Debug, thiserror::Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum CryptoError {
    #[error("cipher finalized twice")]
    FinalizedTwice,
    #[error("openssl error: {0}")]
    Native(String),
}

impl From<OsslError> for CryptoError {
    fn from(e: OsslError) -> Self {
        CryptoError::Native(e.to_string())
    }
}

pub type CryptoResult<T> = Result<T, CryptoError>;
