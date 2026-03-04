// SPDX-FileCopyrightText: Copyright 2026 gematik GmbH
//
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// *******
//
// For additional notes and disclaimer from gematik and in case of changes by gematik,
// find details in the "Readme" file.

use super::channel::{CardChannel, CardChannelError, CommandApdu, FfiCardChannelAdapter, ResponseApdu};
use crate::command::apdu::ApduError;
use crate::command::health_card_status::HealthCardResponseStatus;
use crate::exchange::channel::CardChannel as CoreCardChannel;
use crate::exchange::trusted_channel::establish_trusted_channel_with_cvc_dir;
use crate::exchange::ExchangeError;
use std::path::Path;
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// Options for establishing a trusted channel.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct TrustedChannelOptions {
    /// Directory containing PKI CVC files (input set).
    pub cvc_dir: String,
}

/// Established trusted channel context (contact-based mutual ELC authentication).
#[derive(uniffi::Object)]
pub struct TrustedChannel {
    inner: Mutex<FfiCardChannelAdapter>,
}

/// UniFFI error type for trusted-channel operations.
#[derive(Debug, Clone, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum TrustedChannelError {
    #[error("{reason} (code {code})")]
    Transport { code: u32, reason: String },
    #[error("unexpected card status: {status:?}")]
    UnexpectedStatus { status: HealthCardResponseStatus },
    #[error("card reported status: {status:?}")]
    Status { status: HealthCardResponseStatus },
    #[error("PACE info error: {reason}")]
    PaceInfo { reason: String },
    #[error("crypto error: {error}")]
    Crypto { error: String },
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
    #[error("apdu error: {error}")]
    Apdu { error: ApduError },
}

impl From<ExchangeError> for TrustedChannelError {
    fn from(err: ExchangeError) -> Self {
        match err {
            ExchangeError::Transport { code, message } => Self::Transport { code, reason: message },
            ExchangeError::UnexpectedStatus { status } => Self::UnexpectedStatus { status },
            ExchangeError::Status(status) => Self::Status { status },
            ExchangeError::PaceInfo(inner) => Self::PaceInfo { reason: inner.to_string() },
            ExchangeError::Crypto(inner) => Self::Crypto { error: inner.to_string() },
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
            ExchangeError::Apdu(inner) => Self::Apdu { error: inner },
        }
    }
}

impl From<CardChannelError> for TrustedChannelError {
    fn from(err: CardChannelError) -> Self {
        match err {
            CardChannelError::Transport { code, reason } => Self::Transport { code, reason },
            CardChannelError::Apdu { error } => Self::Apdu { error },
        }
    }
}

/// Establishes a trusted channel (contact-based mutual ELC authentication).
#[uniffi::export]
pub fn establish_trusted_channel(
    session: Arc<dyn CardChannel>,
    options: TrustedChannelOptions,
) -> Result<Arc<TrustedChannel>, TrustedChannelError> {
    let mut adapter = FfiCardChannelAdapter::new(session);
    establish_trusted_channel_with_cvc_dir(&mut adapter, Path::new(&options.cvc_dir))?;
    Ok(Arc::new(TrustedChannel { inner: Mutex::new(adapter) }))
}

#[uniffi::export]
impl TrustedChannel {
    /// Indicates whether the underlying channel supports extended-length APDUs.
    pub fn supports_extended_length(&self) -> bool {
        let guard = self.inner.lock().expect("failed to acquire trusted channel lock");
        guard.supports_extended_length()
    }

    /// Transmits a raw command APDU through the trusted channel.
    pub fn transmit(&self, command: Arc<CommandApdu>) -> Result<Arc<ResponseApdu>, TrustedChannelError> {
        let mut guard = self.inner.lock().map_err(|_| TrustedChannelError::Transport {
            code: 0,
            reason: "Failed to acquire trusted channel lock".to_string(),
        })?;
        let response = guard.transmit(command.as_core()).map_err(TrustedChannelError::from)?;
        Ok(ResponseApdu::from_core(response))
    }
}
