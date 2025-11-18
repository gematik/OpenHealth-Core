use super::session::CardChannel;
use crate::command::apdu::{ApduError, CardCommandApdu, CardResponseApdu};
use crate::exchange::session::CardChannel as ActualCardChannel;
use crate::exchange::trusted_channel;
use crate::exchange::ExchangeError;
use std::sync::{Arc, Mutex};
use thiserror::Error;

struct FfiCardSessionAdapter {
    inner: Arc<dyn CardChannel>,
}

impl ActualCardChannel for FfiCardSessionAdapter {
    type Error = ExchangeError;

    fn supports_extended_length(&self) -> bool {
        self.inner.supports_extended_length()
    }

    fn transmit(&mut self, command: &CardCommandApdu) -> Result<CardResponseApdu, Self::Error> {
        let response = self.inner.transmit(command.apdu()).map_err(ExchangeError::from)?;
        CardResponseApdu::new(&response).map_err(ExchangeError::Apdu)
    }
}

#[derive(uniffi::Object)]
pub struct TrustedChannel {
    inner: Mutex<trusted_channel::TrustedChannel<FfiCardSessionAdapter>>,
}

#[derive(Debug, Clone, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum TrustedChannelError {
    #[error("{message} (code {code})")]
    Transport { code: u32, message: String },
    #[error("unexpected card status: {status}")]
    UnexpectedStatus { status: String },
    #[error("card reported status: {status}")]
    Status { status: String },
    #[error("PACE info error: {message}")]
    PaceInfo { message: String },
    #[error("crypto error: {message}")]
    Crypto { message: String },
    #[error("ASN.1 decode error: {message}")]
    Asn1Decode { message: String },
    #[error("ASN.1 encode error: {message}")]
    Asn1Encode { message: String },
    #[error("GENERAL AUTHENTICATE command error: {message}")]
    GeneralAuthenticateCommand { message: String },
    #[error("MANAGE SECURITY ENVIRONMENT command error: {message}")]
    ManageSecurityEnvironmentCommand { message: String },
    #[error("command composition error: {message}")]
    Command { message: String },
    #[error("pin block error: {message}")]
    PinBlock { message: String },
    #[error("unsupported health-card version")]
    InvalidCardVersion,
    #[error("invalid argument: {message}")]
    InvalidArgument { message: String },
    #[error("mutual authentication failed")]
    MutualAuthenticationFailed,
    #[error("apdu error: {message}")]
    Apdu { message: String },
}

impl TrustedChannelError {
    fn apdu(err: ApduError) -> Self {
        TrustedChannelError::Apdu { message: err.to_string() }
    }
}

impl From<ExchangeError> for TrustedChannelError {
    fn from(err: ExchangeError) -> Self {
        match err {
            ExchangeError::Transport { code, message } => Self::Transport { code, message },
            ExchangeError::UnexpectedStatus { status } => Self::UnexpectedStatus { status: status.to_string() },
            ExchangeError::Status(status) => Self::Status { status: status.to_string() },
            ExchangeError::PaceInfo(inner) => Self::PaceInfo { message: inner.to_string() },
            ExchangeError::Crypto(inner) => Self::Crypto { message: inner.to_string() },
            ExchangeError::Asn1DecoderError(inner) => Self::Asn1Decode { message: inner.to_string() },
            ExchangeError::Asn1EncoderError(inner) => Self::Asn1Encode { message: inner.to_string() },
            ExchangeError::GeneralAuthenticateCommand(inner) => {
                Self::GeneralAuthenticateCommand { message: inner.to_string() }
            }
            ExchangeError::ManageSecurityEnvironmentCommand(inner) => {
                Self::ManageSecurityEnvironmentCommand { message: inner.to_string() }
            }
            ExchangeError::Command(inner) => Self::Command { message: inner.to_string() },
            ExchangeError::PinBlock(inner) => Self::PinBlock { message: inner.to_string() },
            ExchangeError::InvalidCardVersion => Self::InvalidCardVersion,
            ExchangeError::InvalidArgument(message) => Self::InvalidArgument { message: message.to_string() },
            ExchangeError::MutualAuthenticationFailed => Self::MutualAuthenticationFailed,
            ExchangeError::Apdu(inner) => Self::Apdu { message: inner.to_string() },
        }
    }
}

#[uniffi::export]
pub fn establish_trusted_channel(
    session: Arc<dyn CardChannel>,
    card_access_number: String,
) -> Result<Arc<TrustedChannel>, TrustedChannelError> {
    let adapter = FfiCardSessionAdapter { inner: session };
    let established = trusted_channel::establish_trusted_channel(adapter, &card_access_number)?;
    Ok(Arc::new(TrustedChannel { inner: Mutex::new(established) }))
}

#[uniffi::export]
impl TrustedChannel {
    pub fn supports_extended_length(&self) -> Result<bool, TrustedChannelError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| TrustedChannelError::Transport { code: 0, message: "Failed to acquire lock".to_string() })?;
        Ok(guard.channel().supports_extended_length())
    }

    pub fn transmit(&self, command: Vec<u8>) -> Result<Vec<u8>, TrustedChannelError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| TrustedChannelError::Transport { code: 0, message: "Failed to acquire lock".to_string() })?;
        let command = CardCommandApdu::from_bytes(command.as_ref()).map_err(TrustedChannelError::apdu)?;
        let response = guard.transmit(&command).map_err(TrustedChannelError::from)?;
        Ok(response.bytes().to_vec())
    }
}

impl From<trusted_channel::TrustedChannelError> for TrustedChannelError {
    fn from(err: trusted_channel::TrustedChannelError) -> Self {
        match err {
            trusted_channel::TrustedChannelError::Secure(inner)
            | trusted_channel::TrustedChannelError::Transport(inner) => TrustedChannelError::from(inner),
        }
    }
}
