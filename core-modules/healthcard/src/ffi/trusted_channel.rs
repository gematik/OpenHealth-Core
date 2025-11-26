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
    #[error("{reason} (code {code})")]
    Transport { code: u32, reason: String },
    #[error("unexpected card status: {status}")]
    UnexpectedStatus { status: String },
    #[error("card reported status: {status}")]
    Status { status: String },
    #[error("PACE info error: {reason}")]
    PaceInfo { reason: String },
    #[error("crypto error: {reason}")]
    Crypto { reason: String },
    #[error("ASN.1 decode error: {reason}")]
    Asn1Decode { reason: String },
    #[error("ASN.1 encode error: {reason}")]
    Asn1Encode { reason: String },
    #[error("GENERAL AUTHENTICATE command error: {reason}")]
    GeneralAuthenticateCommand { reason: String },
    #[error("MANAGE SECURITY ENVIRONMENT command error: {reason}")]
    ManageSecurityEnvironmentCommand { reason: String },
    #[error("command composition error: {reason}")]
    Command { reason: String },
    #[error("pin block error: {reason}")]
    PinBlock { reason: String },
    #[error("unsupported healthcard version")]
    InvalidCardVersion,
    #[error("invalid argument: {reason}")]
    InvalidArgument { reason: String },
    #[error("mutual authentication failed")]
    MutualAuthenticationFailed,
    #[error("apdu error: {reason}")]
    Apdu { reason: String },
}

impl TrustedChannelError {
    fn apdu(err: ApduError) -> Self {
        TrustedChannelError::Apdu { reason: err.to_string() }
    }
}

impl From<ExchangeError> for TrustedChannelError {
    fn from(err: ExchangeError) -> Self {
        match err {
            ExchangeError::Transport { code, message } => Self::Transport { code, reason: message },
            ExchangeError::UnexpectedStatus { status } => Self::UnexpectedStatus { status: status.to_string() },
            ExchangeError::Status(status) => Self::Status { status: status.to_string() },
            ExchangeError::PaceInfo(inner) => Self::PaceInfo { reason: inner.to_string() },
            ExchangeError::Crypto(inner) => Self::Crypto { reason: inner.to_string() },
            ExchangeError::Asn1DecoderError(inner) => Self::Asn1Decode { reason: inner.to_string() },
            ExchangeError::Asn1EncoderError(inner) => Self::Asn1Encode { reason: inner.to_string() },
            ExchangeError::GeneralAuthenticateCommand(inner) => {
                Self::GeneralAuthenticateCommand { reason: inner.to_string() }
            }
            ExchangeError::ManageSecurityEnvironmentCommand(inner) => {
                Self::ManageSecurityEnvironmentCommand { reason: inner.to_string() }
            }
            ExchangeError::Command(inner) => Self::Command { reason: inner.to_string() },
            ExchangeError::PinBlock(inner) => Self::PinBlock { reason: inner.to_string() },
            ExchangeError::InvalidCardVersion => Self::InvalidCardVersion,
            ExchangeError::InvalidArgument(reason) => Self::InvalidArgument { reason: reason.to_string() },
            ExchangeError::MutualAuthenticationFailed => Self::MutualAuthenticationFailed,
            ExchangeError::Apdu(inner) => Self::Apdu { reason: inner.to_string() },
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
            .map_err(|_| TrustedChannelError::Transport { code: 0, reason: "Failed to acquire lock".to_string() })?;
        Ok(guard.channel().supports_extended_length())
    }

    pub fn transmit(&self, command: Vec<u8>) -> Result<Vec<u8>, TrustedChannelError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| TrustedChannelError::Transport { code: 0, reason: "Failed to acquire lock".to_string() })?;
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
