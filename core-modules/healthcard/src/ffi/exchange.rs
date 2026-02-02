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

use super::channel::{CardChannel, FfiCardChannelAdapter};
use crate::command::apdu::ApduError;
use crate::command::health_card_command::HealthCardResponse as CoreHealthCardResponse;
use crate::command::health_card_status::HealthCardResponseStatus;
use crate::exchange::certificate::CertificateFile;
use crate::exchange::{self, ExchangeError as CoreExchangeError, HealthCardVerifyPinResult};
use std::sync::Arc;
use thiserror::Error;
use zeroize::Zeroize;

/// PIN/secret value used for card operations.
///
/// The input string is zeroized after parsing. Treat PIN values and derived data as secrets.
#[derive(uniffi::Object)]
pub struct CardPin {
    inner: exchange::CardPin,
}

impl CardPin {
    pub(crate) fn as_core(&self) -> &exchange::CardPin {
        &self.inner
    }
}

#[uniffi::export]
impl CardPin {
    /// Creates a PIN from a digit string (e.g. `"123456"`).
    ///
    /// The provided string is zeroized in memory after parsing.
    #[uniffi::constructor]
    pub fn from_digits(digits: String) -> Result<Self, ExchangeError> {
        let mut digits = digits;
        let result = exchange::CardPin::new(&digits).map_err(CoreExchangeError::from);
        digits.zeroize();
        Ok(Self { inner: result? })
    }
}

/// High-level outcome of a PIN verification attempt.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum VerifyPinOutcome {
    Success,
    WrongSecretWarning,
    CardBlocked,
}

/// FFI-friendly response for health card commands.
///
/// `status` is derived from `sw` and is suitable for application-level branching.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct HealthCardResponse {
    pub status: HealthCardResponseStatus,
    pub sw: u16,
    pub data: Vec<u8>,
}

impl From<CoreHealthCardResponse> for HealthCardResponse {
    fn from(response: CoreHealthCardResponse) -> Self {
        let sw = response.apdu.sw();
        let data = response.apdu.to_data();
        HealthCardResponse { status: response.status, sw, data }
    }
}

/// Result for `verify_pin`, including outcome and (optional) remaining retries.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct VerifyPinResult {
    pub outcome: VerifyPinOutcome,
    pub response: HealthCardResponse,
    pub retries_left: Option<u8>,
}

impl VerifyPinResult {
    pub(crate) fn from_core(result: HealthCardVerifyPinResult) -> Self {
        match result {
            HealthCardVerifyPinResult::Success(response) => {
                VerifyPinResult { outcome: VerifyPinOutcome::Success, response: response.into(), retries_left: None }
            }
            HealthCardVerifyPinResult::WrongSecretWarning { response, retries_left } => VerifyPinResult {
                outcome: VerifyPinOutcome::WrongSecretWarning,
                response: response.into(),
                retries_left: Some(retries_left),
            },
            HealthCardVerifyPinResult::CardBlocked(response) => VerifyPinResult {
                outcome: VerifyPinOutcome::CardBlocked,
                response: response.into(),
                retries_left: None,
            },
        }
    }
}

/// UniFFI error type for exchange operations.
///
/// This mirrors `crate::exchange::ExchangeError` but uses FFI-friendly payloads (strings/records).
#[derive(Debug, Clone, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum ExchangeError {
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

impl From<CoreExchangeError> for ExchangeError {
    fn from(err: CoreExchangeError) -> Self {
        match err {
            CoreExchangeError::Transport { code, message } => Self::Transport { code, reason: message },
            CoreExchangeError::UnexpectedStatus { status } => Self::UnexpectedStatus { status },
            CoreExchangeError::Status(status) => Self::Status { status },
            CoreExchangeError::PaceInfo(inner) => Self::PaceInfo { reason: inner.to_string() },
            CoreExchangeError::Crypto(inner) => Self::Crypto { error: inner.to_string() },
            CoreExchangeError::Asn1DecoderError(inner) => Self::Asn1Decode { reason: inner.to_string() },
            CoreExchangeError::Asn1EncoderError(inner) => Self::Asn1Encode { reason: inner.to_string() },
            CoreExchangeError::GeneralAuthenticateCommand(inner) => {
                Self::GeneralAuthenticateCommand { reason: inner.to_string() }
            }
            CoreExchangeError::ManageSecurityEnvironmentCommand(inner) => {
                Self::ManageSecurityEnvironmentCommand { reason: inner.to_string() }
            }
            CoreExchangeError::Command(inner) => Self::Command { reason: inner.to_string() },
            CoreExchangeError::PinBlock(inner) => Self::PinBlock { reason: inner.to_string() },
            CoreExchangeError::InvalidCardVersion => Self::InvalidCardVersion,
            CoreExchangeError::InvalidArgument(reason) => Self::InvalidArgument { reason: reason.to_string() },
            CoreExchangeError::MutualAuthenticationFailed => Self::MutualAuthenticationFailed,
            CoreExchangeError::Apdu(inner) => Self::Apdu { error: inner },
        }
    }
}

fn with_channel<T, F>(session: Arc<dyn CardChannel>, op: F) -> Result<T, ExchangeError>
where
    F: FnOnce(&mut FfiCardChannelAdapter) -> Result<T, CoreExchangeError>,
{
    let mut adapter = FfiCardChannelAdapter::new(session);
    op(&mut adapter).map_err(ExchangeError::from)
}

/// Verifies a PIN against the card.
///
/// This is a stateless helper that performs the necessary APDU exchange(s) on the provided
/// `session`. For workflows that require PACE/secure messaging, use `secure_channel` APIs.
#[uniffi::export]
pub fn verify_pin(session: Arc<dyn CardChannel>, pin: Arc<CardPin>) -> Result<VerifyPinResult, ExchangeError> {
    with_channel(session, |adapter| {
        let result = exchange::verify_pin(adapter, pin.as_core())?;
        Ok(VerifyPinResult::from_core(result))
    })
}

/// Unlocks the home PIN using the PUK (reset retry counter).
#[uniffi::export]
pub fn unlock_egk_with_puk(
    session: Arc<dyn CardChannel>,
    puk: Arc<CardPin>,
) -> Result<HealthCardResponseStatus, ExchangeError> {
    with_channel(session, |adapter| exchange::unlock_egk_with_puk(adapter, puk.as_core()))
}

/// Changes the home PIN using the old PIN.
#[uniffi::export]
pub fn change_pin(
    session: Arc<dyn CardChannel>,
    old_pin: Arc<CardPin>,
    new_pin: Arc<CardPin>,
) -> Result<HealthCardResponseStatus, ExchangeError> {
    with_channel(session, |adapter| exchange::change_pin(adapter, old_pin.as_core(), new_pin.as_core()))
}

/// Changes the home PIN using the PUK (reset retry counter + new PIN).
#[uniffi::export]
pub fn change_pin_with_puk(
    session: Arc<dyn CardChannel>,
    puk: Arc<CardPin>,
    new_pin: Arc<CardPin>,
) -> Result<HealthCardResponseStatus, ExchangeError> {
    with_channel(session, |adapter| exchange::change_pin_with_puk(adapter, puk.as_core(), new_pin.as_core()))
}

/// Returns `length` bytes of random data from the card.
#[uniffi::export]
pub fn get_random(session: Arc<dyn CardChannel>, length: u32) -> Result<Vec<u8>, ExchangeError> {
    with_channel(session, |adapter| exchange::get_random(adapter, length as usize))
}

/// Reads the VSD container from the card (if available).
#[uniffi::export]
pub fn read_vsd(session: Arc<dyn CardChannel>) -> Result<Vec<u8>, ExchangeError> {
    with_channel(session, exchange::read_vsd)
}

/// Signs the given challenge with the card's signing key.
#[uniffi::export]
pub fn sign_challenge(session: Arc<dyn CardChannel>, challenge: Vec<u8>) -> Result<Vec<u8>, ExchangeError> {
    with_channel(session, |adapter| exchange::sign_challenge(adapter, &challenge))
}

/// Retrieves the default certificate from the card.
#[uniffi::export]
pub fn retrieve_certificate(session: Arc<dyn CardChannel>) -> Result<Vec<u8>, ExchangeError> {
    with_channel(session, exchange::retrieve_certificate)
}

/// Retrieves a specific certificate file from the card.
#[uniffi::export]
pub fn retrieve_certificate_from(
    session: Arc<dyn CardChannel>,
    certificate: CertificateFile,
) -> Result<Vec<u8>, ExchangeError> {
    with_channel(session, |adapter| exchange::retrieve_certificate_from(adapter, certificate))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::apdu::CardResponseApdu;
    use crate::command::health_card_command::HealthCardResponse as CoreHealthCardResponse;
    use crate::command::health_card_status::HealthCardResponseStatus;
    use crate::exchange::ExchangeError as CoreExchangeError;
    use crate::exchange::HealthCardVerifyPinResult as CoreVerifyPinResult;
    use crate::ffi::channel;
    use asn1::error::Asn1DecoderError;
    use std::sync::Arc;

    fn response(status: HealthCardResponseStatus) -> CoreHealthCardResponse {
        let apdu = CardResponseApdu::new(&[0x90, 0x00]).unwrap();
        CoreHealthCardResponse::new(status, apdu)
    }

    #[test]
    fn verify_pin_result_mapping() {
        let success =
            VerifyPinResult::from_core(CoreVerifyPinResult::Success(response(HealthCardResponseStatus::Success)));
        assert!(matches!(success.outcome, VerifyPinOutcome::Success));
        assert_eq!(success.retries_left, None);

        let warn = VerifyPinResult::from_core(CoreVerifyPinResult::WrongSecretWarning {
            response: response(HealthCardResponseStatus::WrongSecretWarningCount02),
            retries_left: 2,
        });
        assert!(matches!(warn.outcome, VerifyPinOutcome::WrongSecretWarning));
        assert_eq!(warn.retries_left, Some(2));
    }

    #[test]
    fn exchange_error_mapping() {
        let err: ExchangeError = CoreExchangeError::InvalidArgument("bad".to_string()).into();
        match err {
            ExchangeError::InvalidArgument { reason } => assert_eq!(reason, "bad"),
            _ => panic!("expected invalid argument"),
        }

        let err: ExchangeError = CoreExchangeError::Asn1DecoderError(Asn1DecoderError::MalformedUtf8String).into();
        match err {
            ExchangeError::Asn1Decode { reason } => assert!(reason.contains("Malformed UTF-8 string")),
            _ => panic!("expected asn1 decode"),
        }
    }

    #[test]
    fn card_pin_from_digits_errors_on_non_digit() {
        let err = CardPin::from_digits("12a4".to_string()).err().unwrap();
        assert!(matches!(err, ExchangeError::PinBlock { .. }));
    }

    #[test]
    fn with_channel_maps_errors() {
        struct DummyChannel;

        impl CardChannel for DummyChannel {
            fn supports_extended_length(&self) -> bool {
                false
            }

            fn transmit(
                &self,
                _command: Arc<channel::CommandApdu>,
            ) -> Result<Arc<channel::ResponseApdu>, channel::CardChannelError> {
                unreachable!()
            }
        }

        let session: Arc<dyn CardChannel> = Arc::new(DummyChannel);
        let err = super::with_channel(session, |_adapter| -> Result<(), CoreExchangeError> {
            Err(CoreExchangeError::InvalidArgument("boom".to_string()))
        })
        .unwrap_err();
        assert!(matches!(err, ExchangeError::InvalidArgument { reason } if reason == "boom"));
    }
}
