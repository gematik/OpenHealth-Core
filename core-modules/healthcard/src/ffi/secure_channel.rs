// SPDX-FileCopyrightText: Copyright 2025 - 2026 gematik GmbH
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

use super::channel::{CardChannel, CommandApdu, FfiCardChannelAdapter, ResponseApdu};
use super::exchange::{CardPin, VerifyPinResult};
use crate::command::apdu::ApduError;
use crate::command::health_card_status::HealthCardResponseStatus;
use crate::exchange::certificate::CertificateFile;
use crate::exchange::channel::CardChannel as CoreCardChannel;
use crate::exchange::secure_channel::{self, CardAccessNumber as ActualCardAccessNumber};
use crate::exchange::ExchangeError;
use crate::exchange::{
    change_pin as exchange_change_pin, change_pin_with_puk as exchange_change_pin_with_puk,
    unlock_egk_with_puk as exchange_unlock_egk_with_puk,
};
use crypto::ec::ec_key::{EcCurve, EcPrivateKey};
use crypto::error::CryptoError;
use num_bigint::{BigInt, Sign};
use std::convert::TryInto;
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// Card Access Number (CAN) used during PACE establishment.
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
    /// Creates a CAN from a 6-digit string (e.g. `"123456"`).
    #[uniffi::constructor]
    pub fn from_digits(digits: String) -> Result<Self, SecureChannelError> {
        let bytes = digits.into_bytes();
        let arr: [u8; 6] = bytes
            .try_into()
            .map_err(|_| SecureChannelError::InvalidArgument { reason: "CAN must be exactly 6 digits".into() })?;
        let inner = ActualCardAccessNumber::from_digits(arr)?;
        Ok(Self { inner })
    }

    /// Returns the CAN digits as a string.
    pub fn digits(&self) -> String {
        String::from_utf8_lossy(self.inner.as_bytes()).into_owned()
    }
}

/// Established secure messaging context (PACE + mutual authentication).
///
/// This object wraps a core `SecureChannel` and uses a mutex to serialize access.
/// Use it for repeated operations after PACE establishment.
#[derive(uniffi::Object)]
pub struct SecureChannel {
    inner: Mutex<secure_channel::SecureChannel<FfiCardChannelAdapter>>,
}

/// UniFFI error type for secure-channel operations.
///
/// This maps core `ExchangeError`/`SecureChannelError` into an FFI-friendly representation.
#[derive(Debug, Clone, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum SecureChannelError {
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

impl From<ExchangeError> for SecureChannelError {
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

/// Establishes a secure channel (PACE) over the given card session.
///
/// The returned `SecureChannel` can be used to transmit protected APDUs and to call higher-level
/// operations (PIN verify, certificate retrieval, etc.) with secure messaging.
#[uniffi::export]
pub fn establish_secure_channel(
    session: Arc<dyn CardChannel>,
    card_access_number: Arc<CardAccessNumber>,
) -> Result<Arc<SecureChannel>, SecureChannelError> {
    let adapter = FfiCardChannelAdapter::new(session);
    let established = secure_channel::establish_secure_channel(adapter, card_access_number.as_core())?;
    Ok(Arc::new(SecureChannel { inner: Mutex::new(established) }))
}

/// Establishes a secure channel (PACE) using deterministic private keys.
///
/// The `keys` input must contain at least two hex-encoded private keys which are used
/// in order during PACE establishment. This is intended for transcript replay tests.
#[uniffi::export]
pub fn establish_secure_channel_with_keys(
    session: Arc<dyn CardChannel>,
    card_access_number: Arc<CardAccessNumber>,
    keys: Vec<String>,
) -> Result<Arc<SecureChannel>, SecureChannelError> {
    if keys.len() < 2 {
        return Err(SecureChannelError::InvalidArgument { reason: "at least 2 keys required".to_string() });
    }

    let decoded = keys
        .iter()
        .enumerate()
        .map(|(index, key)| {
            hex::decode(key).map_err(|err| SecureChannelError::InvalidArgument {
                reason: format!("invalid key hex at index {index}: {err}"),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    let mut key_iter = decoded.into_iter();
    let adapter = FfiCardChannelAdapter::new(session);
    let established =
        secure_channel::establish_secure_channel_with(adapter, card_access_number.as_core(), move |curve: EcCurve| {
            let key_bytes =
                key_iter.next().ok_or(CryptoError::InvalidKeyMaterial { context: "missing fixed key material" })?;
            let private_key = EcPrivateKey::from_bytes(curve.clone(), key_bytes);
            let scalar = BigInt::from_bytes_be(Sign::Plus, private_key.as_bytes());
            let public_key = curve.g().mul(&scalar)?.to_ec_public_key()?;
            Ok((public_key, private_key))
        })?;
    Ok(Arc::new(SecureChannel { inner: Mutex::new(established) }))
}

impl SecureChannel {
    fn with_locked<T, F>(&self, op: F) -> Result<T, SecureChannelError>
    where
        F: FnOnce(&mut secure_channel::SecureChannel<FfiCardChannelAdapter>) -> Result<T, ExchangeError>,
    {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SecureChannelError::Transport { code: 0, reason: "Failed to acquire lock".to_string() })?;
        op(&mut guard).map_err(SecureChannelError::from)
    }
}

#[uniffi::export]
impl SecureChannel {
    /// Indicates whether the underlying channel supports extended-length APDUs.
    pub fn supports_extended_length(&self) -> bool {
        let mut guard = self.inner.lock().expect("failed to acquire secure channel lock for supports_extended_length");
        guard.channel().supports_extended_length()
    }

    /// Transmits a raw command APDU through the secure channel and returns a response APDU.
    pub fn transmit(&self, command: Arc<CommandApdu>) -> Result<Arc<ResponseApdu>, SecureChannelError> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| SecureChannelError::Transport { code: 0, reason: "Failed to acquire lock".to_string() })?;
        let response = guard.transmit(command.as_core()).map_err(SecureChannelError::from)?;
        Ok(ResponseApdu::from_core(response))
    }

    /// Verifies a PIN using the secure messaging context.
    pub fn verify_pin(&self, pin: Arc<CardPin>) -> Result<VerifyPinResult, SecureChannelError> {
        self.with_locked(|channel| {
            let result = crate::exchange::verify_pin(channel, pin.as_core())?;
            Ok(VerifyPinResult::from_core(result))
        })
    }

    /// Unlocks the home PIN using the PUK (reset retry counter).
    pub fn unlock_egk_with_puk(&self, puk: Arc<CardPin>) -> Result<HealthCardResponseStatus, SecureChannelError> {
        self.with_locked(|channel| exchange_unlock_egk_with_puk(channel, puk.as_core()))
    }

    /// Changes the home PIN using the old PIN.
    pub fn change_pin(
        &self,
        old_pin: Arc<CardPin>,
        new_pin: Arc<CardPin>,
    ) -> Result<HealthCardResponseStatus, SecureChannelError> {
        self.with_locked(|channel| exchange_change_pin(channel, old_pin.as_core(), new_pin.as_core()))
    }

    /// Changes the home PIN using the PUK (reset retry counter + new PIN).
    pub fn change_pin_with_puk(
        &self,
        puk: Arc<CardPin>,
        new_pin: Arc<CardPin>,
    ) -> Result<HealthCardResponseStatus, SecureChannelError> {
        self.with_locked(|channel| exchange_change_pin_with_puk(channel, puk.as_core(), new_pin.as_core()))
    }

    /// Returns `length` bytes of random data from the card.
    pub fn get_random(&self, length: u32) -> Result<Vec<u8>, SecureChannelError> {
        self.with_locked(|channel| crate::exchange::get_random(channel, length as usize))
    }

    /// Reads the VSD container from the card (if available).
    pub fn read_vsd(&self) -> Result<Vec<u8>, SecureChannelError> {
        self.with_locked(crate::exchange::read_vsd)
    }

    /// Signs the given challenge with the card's signing key.
    pub fn sign_challenge(&self, challenge: Vec<u8>) -> Result<Vec<u8>, SecureChannelError> {
        self.with_locked(|channel| crate::exchange::sign_challenge(channel, &challenge))
    }

    /// Retrieves the default certificate from the card.
    pub fn retrieve_certificate(&self) -> Result<Vec<u8>, SecureChannelError> {
        self.with_locked(crate::exchange::retrieve_certificate)
    }

    /// Retrieves a specific certificate file from the card.
    pub fn retrieve_certificate_from(&self, certificate: CertificateFile) -> Result<Vec<u8>, SecureChannelError> {
        self.with_locked(|channel| crate::exchange::retrieve_certificate_from(channel, certificate))
    }
}

impl From<secure_channel::SecureChannelError> for SecureChannelError {
    fn from(err: secure_channel::SecureChannelError) -> Self {
        match err {
            secure_channel::SecureChannelError::Secure(inner)
            | secure_channel::SecureChannelError::Transport(inner) => SecureChannelError::from(inner),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::apdu::CardCommandApdu;
    use crate::exchange::ExchangeError as CoreExchangeError;
    use crate::ffi::channel::CardChannelError;
    use std::sync::{Arc, Mutex};

    struct DummyForeign;

    impl CardChannel for DummyForeign {
        fn supports_extended_length(&self) -> bool {
            true
        }

        fn transmit(&self, command: Arc<CommandApdu>) -> Result<Arc<ResponseApdu>, CardChannelError> {
            let core = command.as_core();
            assert_eq!(core.cla(), 0x00);
            assert_eq!(core.ins(), 0xA4);
            assert_eq!(core.p1(), 0x04);
            assert_eq!(core.p2(), 0x00);
            assert!(core.as_data().is_none());
            assert_eq!(core.expected_length(), None);
            Ok(Arc::new(ResponseApdu::from_parts(0x9000, vec![0xDE, 0xAD]).unwrap()))
        }
    }

    #[test]
    fn adapter_wraps_response_apdu() {
        let inner: Arc<dyn CardChannel> = Arc::new(DummyForeign);
        let mut adapter = FfiCardChannelAdapter::new(inner);
        let apdu = CardCommandApdu::header_only(0x00, 0xA4, 0x04, 0x00).unwrap();
        let response = CoreCardChannel::transmit(&mut adapter, &apdu).unwrap();
        assert_eq!(response.sw(), 0x9000);
        assert_eq!(response.to_data(), vec![0xDE, 0xAD]);
    }

    #[test]
    fn card_access_number_roundtrip() {
        let can = CardAccessNumber::from_digits("123456".to_string()).unwrap();
        assert_eq!(can.digits(), "123456");
    }

    #[test]
    fn card_access_number_requires_six_digits() {
        match CardAccessNumber::from_digits("12345".to_string()) {
            Err(err) => assert!(matches!(err, SecureChannelError::InvalidArgument { .. })),
            Ok(_) => panic!("expected invalid argument"),
        }
    }

    #[test]
    fn establish_secure_channel_requires_two_keys() {
        let session: Arc<dyn CardChannel> = Arc::new(DummyForeign);
        let can = Arc::new(CardAccessNumber::from_digits("123456".to_string()).unwrap());
        match establish_secure_channel_with_keys(session, can, vec!["AA".to_string()]) {
            Err(SecureChannelError::InvalidArgument { reason }) => assert!(reason.contains("at least 2 keys required")),
            Err(_) => panic!("expected invalid argument"),
            Ok(_) => panic!("expected invalid argument"),
        }
    }

    #[test]
    fn establish_secure_channel_rejects_invalid_key_hex() {
        let session: Arc<dyn CardChannel> = Arc::new(DummyForeign);
        let can = Arc::new(CardAccessNumber::from_digits("123456".to_string()).unwrap());
        match establish_secure_channel_with_keys(session, can, vec!["ZZ".to_string(), "00".to_string()]) {
            Err(SecureChannelError::InvalidArgument { reason }) => {
                assert!(reason.contains("invalid key hex at index 0"))
            }
            Err(_) => panic!("expected invalid argument"),
            Ok(_) => panic!("expected invalid argument"),
        }
    }

    #[test]
    fn exchange_error_mapping() {
        let err: SecureChannelError = CoreExchangeError::InvalidArgument("bad".to_string()).into();
        match err {
            SecureChannelError::InvalidArgument { reason } => assert_eq!(reason, "bad"),
            _ => panic!("expected invalid argument"),
        }
    }

    #[test]
    fn card_access_number_rejects_non_digits() {
        let err = CardAccessNumber::from_digits("12A456".to_string()).err().unwrap();
        assert!(matches!(err, SecureChannelError::InvalidArgument { .. }));
    }

    #[test]
    fn secure_channel_lock_and_transmit_paths() {
        struct ErrorForeign;

        impl CardChannel for ErrorForeign {
            fn supports_extended_length(&self) -> bool {
                true
            }

            fn transmit(&self, _command: Arc<CommandApdu>) -> Result<Arc<ResponseApdu>, CardChannelError> {
                Err(CardChannelError::Transport { code: 0, reason: "no card".into() })
            }
        }

        let inner: Arc<dyn CardChannel> = Arc::new(ErrorForeign);
        let adapter = FfiCardChannelAdapter::new(inner);
        let core = crate::exchange::secure_channel::test_secure_channel_with_adapter(adapter);
        let secure = SecureChannel { inner: Mutex::new(core) };

        let ok = secure.with_locked(|_channel| Ok(()));
        assert!(ok.is_ok());

        let command = Arc::new(CommandApdu::header_only(0x00, 0xA4, 0x04, 0x00).unwrap());
        let err = secure.transmit(command).unwrap_err();
        assert!(matches!(err, SecureChannelError::Transport { .. }));
    }
}
