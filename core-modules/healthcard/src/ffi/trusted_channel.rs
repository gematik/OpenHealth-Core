// SPDX-FileCopyrightText: Copyright 2025 gematik GmbH
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

use super::channel::{CardChannel, CardChannelError, CommandApdu, ResponseApdu};
use crate::command::apdu::{CardCommandApdu, CardResponseApdu};
use crate::command::health_card_status::HealthCardResponseStatus;
use crate::exchange::channel::CardChannel as CoreCardChannel;
use crate::exchange::trusted_channel::{self, CardAccessNumber as ActualCardAccessNumber};
use crate::exchange::ExchangeError;
use crate::command::apdu::ApduError;
use std::convert::TryInto;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(uniffi::Object)]
pub struct CardAccessNumber {
    inner: ActualCardAccessNumber,
}

impl CardAccessNumber {
    fn as_core(&self) -> &ActualCardAccessNumber {
        &self.inner
    }
}

#[uniffi::export]
impl CardAccessNumber {
    #[uniffi::constructor]
    pub fn from_digits(digits: String) -> Result<Self, TrustedChannelError> {
        let bytes = digits.into_bytes();
        let arr: [u8; 6] = bytes
            .try_into()
            .map_err(|_| TrustedChannelError::InvalidArgument { reason: "CAN must be exactly 6 digits".into() })?;
        let inner = ActualCardAccessNumber::from_digits(arr)?;
        Ok(Self { inner })
    }

    pub fn digits(&self) -> String {
        String::from_utf8_lossy(self.inner.as_bytes()).into_owned()
    }
}

struct FfiCardChannelAdapter {
    inner: Arc<dyn CardChannel>,
    serialize: Mutex<()>,
}

impl CoreCardChannel for FfiCardChannelAdapter {
    type Error = CardChannelError;

    fn supports_extended_length(&self) -> bool {
        let _guard = self.serialize.lock().expect("card channel lock poisoned (supports_extended_length)");
        self.inner.supports_extended_length()
    }

    fn transmit(&mut self, command: &CardCommandApdu) -> Result<CardResponseApdu, Self::Error> {
        let _guard = self
            .serialize
            .lock()
            .map_err(|_| CardChannelError::Transport { code: 0, reason: "card channel lock poisoned".into() })?;
        let response = self.inner.transmit(CommandApdu::from_core(command.clone()))?;
        CardResponseApdu::try_from(response).map_err(CardChannelError::from)
    }
}

#[derive(uniffi::Object)]
pub struct TrustedChannel {
    inner: Mutex<trusted_channel::TrustedChannel<FfiCardChannelAdapter>>,
}

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

#[uniffi::export]
pub fn establish_trusted_channel(
    session: Arc<dyn CardChannel>,
    card_access_number: Arc<CardAccessNumber>,
) -> Result<Arc<TrustedChannel>, TrustedChannelError> {
    let adapter = FfiCardChannelAdapter { inner: session, serialize: Mutex::new(()) };
    let established = trusted_channel::establish_trusted_channel(adapter, card_access_number.as_core())?;
    Ok(Arc::new(TrustedChannel { inner: Mutex::new(established) }))
}

#[uniffi::export]
impl TrustedChannel {
    pub fn supports_extended_length(&self) -> bool {
        let mut guard = self.inner.lock().expect("failed to acquire trusted channel lock for supports_extended_length");
        guard.channel().supports_extended_length()
    }

    pub fn transmit(&self, command: Arc<CommandApdu>) -> Result<ResponseApdu, TrustedChannelError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| TrustedChannelError::Transport { code: 0, reason: "Failed to acquire lock".to_string() })?;
        let response = guard.transmit(command.as_core()).map_err(TrustedChannelError::from)?;
        Ok(ResponseApdu::from(response))
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::channel::CardChannel as CoreCardChannel;
    use std::sync::Arc;

    struct DummyForeign;

    impl CardChannel for DummyForeign {
        fn supports_extended_length(&self) -> bool {
            true
        }

        fn transmit(&self, command: Arc<CommandApdu>) -> Result<ResponseApdu, CardChannelError> {
            let core = command.as_core();
            assert_eq!(core.cla(), 0x00);
            assert_eq!(core.ins(), 0xA4);
            assert_eq!(core.p1(), 0x04);
            assert_eq!(core.p2(), 0x00);
            assert!(core.as_data().is_none());
            assert_eq!(core.expected_length(), None);
            Ok(ResponseApdu { sw: 0x9000, status: HealthCardResponseStatus::Success, data: vec![0xDE, 0xAD] })
        }
    }

    #[test]
    fn adapter_wraps_response_apdu() {
        let inner: Arc<dyn CardChannel> = Arc::new(DummyForeign);
        let mut adapter = FfiCardChannelAdapter { inner, serialize: Mutex::new(()) };
        let apdu = CardCommandApdu::header_only(0x00, 0xA4, 0x04, 0x00).unwrap();
        let response = CoreCardChannel::transmit(&mut adapter, &apdu).unwrap();
        assert_eq!(response.sw(), 0x9000);
        assert_eq!(response.to_data(), vec![0xDE, 0xAD]);
    }
}
