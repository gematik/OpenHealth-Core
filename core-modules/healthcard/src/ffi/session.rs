use crate::exchange::ExchangeError;
use crate::ffi::trusted_channel::TrustedChannelError;
use thiserror::Error;

/// Error type returned by the foreign card channel implementation.
#[derive(Debug, Clone, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum CardChannelError {
    #[error("transport error: {0}")]
    Transport(#[from] TrustedChannelError),
}

#[uniffi::export(with_foreign)]
pub trait CardChannel: Send + Sync {
    fn supports_extended_length(&self) -> bool;

    fn transmit(&self, command: Vec<u8>) -> Result<Vec<u8>, CardChannelError>;
}

impl From<CardChannelError> for ExchangeError {
    fn from(err: CardChannelError) -> Self {
        match err {
            CardChannelError::Transport(inner) => match inner {
                TrustedChannelError::Transport { code, reason } => ExchangeError::Transport { code, message: reason },
                other => ExchangeError::Transport { code: 0, message: other.to_string() },
            },
        }
    }
}
