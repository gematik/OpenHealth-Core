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

use crate::command::apdu::{ApduError, CardCommandApdu, CardResponseApdu};
use crate::command::health_card_status::{HealthCardResponseStatus, StatusWordExt};
use crate::exchange::channel::CardChannel as CoreCardChannel;
use crate::exchange::ExchangeError;
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// ISO 7816 command APDU for UniFFI.
///
/// This wraps the core `CardCommandApdu` and exposes constructors and `to_bytes()` for
/// cross-language callers.
///
/// Length parameters are expressed as `u32`. Values outside the supported APDU ranges return
/// `ApduError::InvalidLength`.
#[derive(Debug, uniffi::Object)]
pub struct CommandApdu {
    inner: CardCommandApdu,
}

impl CommandApdu {
    pub(crate) fn from_core(command: CardCommandApdu) -> Arc<Self> {
        Arc::new(Self { inner: command })
    }

    pub fn as_core(&self) -> &CardCommandApdu {
        &self.inner
    }

    #[cfg(test)]
    pub fn to_core(&self) -> CardCommandApdu {
        self.inner.clone()
    }
}

#[uniffi::export]
impl CommandApdu {
    /// Creates a case 1 APDU (header only, no data, no expected length).
    #[uniffi::constructor]
    pub fn header_only(cla: u8, ins: u8, p1: u8, p2: u8) -> Result<Self, ApduError> {
        Ok(Self { inner: CardCommandApdu::header_only(cla, ins, p1, p2)? })
    }

    /// Parses an APDU from raw bytes.
    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ApduError> {
        Ok(Self { inner: CardCommandApdu::from_bytes(&bytes)? })
    }

    /// Creates an APDU with an expected response length (`Le`).
    ///
    /// Note: For "wildcard" semantics, pass `expected_length = 65536` (extended-length encoding)
    /// or `expected_length = 256` (short-length encoding). The exact encoding depends on
    /// `length_class` and is handled by the core APDU implementation.
    #[uniffi::constructor]
    pub fn with_expect(
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        length_class: crate::command::apdu::LengthClass,
        expected_length: u32,
    ) -> Result<Self, ApduError> {
        let expected_length = usize::try_from(expected_length)
            .map_err(|_| ApduError::InvalidLength("expected_length does not fit into usize".into()))?;
        Ok(Self { inner: CardCommandApdu::with_expect(cla, ins, p1, p2, length_class, expected_length)? })
    }

    /// Creates an APDU with command data (`Lc` + data), without an expected response length.
    #[uniffi::constructor]
    pub fn with_data(
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        length_class: crate::command::apdu::LengthClass,
        data: Vec<u8>,
    ) -> Result<Self, ApduError> {
        Ok(Self { inner: CardCommandApdu::with_data(cla, ins, p1, p2, length_class, data)? })
    }

    /// Creates an APDU with command data (`Lc` + data) and an expected response length (`Le`).
    #[uniffi::constructor]
    pub fn with_data_and_expect(
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        length_class: crate::command::apdu::LengthClass,
        data: Vec<u8>,
        expected_length: u32,
    ) -> Result<Self, ApduError> {
        let expected_length = usize::try_from(expected_length)
            .map_err(|_| ApduError::InvalidLength("expected_length does not fit into usize".into()))?;
        Ok(Self {
            inner: CardCommandApdu::with_data_and_expect(cla, ins, p1, p2, length_class, data, expected_length)?,
        })
    }

    /// Serializes the APDU to raw bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
}

/// ISO 7816 response APDU for UniFFI.
///
/// This object represents a response APDU and exposes:
/// - `sw()`: status word (SW1SW2)
/// - `data()`: response data without the status word
/// - `status()`: interpreted high-level status (derived from `sw`)
/// - `to_bytes()`: raw APDU bytes (`data || SW1 || SW2`)
#[derive(Debug, uniffi::Object)]
pub struct ResponseApdu {
    inner: CardResponseApdu,
}

impl From<CardResponseApdu> for ResponseApdu {
    fn from(response: CardResponseApdu) -> Self {
        ResponseApdu { inner: response }
    }
}

impl ResponseApdu {
    pub(crate) fn from_core(response: CardResponseApdu) -> Arc<Self> {
        Arc::new(ResponseApdu { inner: response })
    }
}

impl TryFrom<&ResponseApdu> for CardResponseApdu {
    type Error = ApduError;

    fn try_from(response: &ResponseApdu) -> Result<Self, Self::Error> {
        Ok(response.inner.clone())
    }
}

#[uniffi::export]
impl ResponseApdu {
    /// Parses a response APDU from raw bytes.
    ///
    /// The input is expected to contain at least SW1SW2 (2 bytes).
    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ApduError> {
        Ok(ResponseApdu { inner: CardResponseApdu::from_bytes(&bytes)? })
    }

    /// Creates a response APDU from `sw` (SW1SW2) and response `data`.
    ///
    /// `sw` is interpreted as big-endian (SW1<<8 | SW2).
    #[uniffi::constructor]
    pub fn from_parts(sw: u16, data: Vec<u8>) -> Result<Self, ApduError> {
        let mut full = data;
        full.push((sw >> 8) as u8);
        full.push(sw as u8);
        Ok(ResponseApdu { inner: CardResponseApdu::new(&full)? })
    }

    pub fn sw(&self) -> u16 {
        self.inner.sw()
    }

    /// Returns a high-level status derived from `sw()`.
    ///
    /// Note: Status word interpretation depends on the command context. This method uses the
    /// mapping for the `GENERAL AUTHENTICATE` command, which is what most higher-level workflows
    /// in this crate use. If you need a different mapping, use `sw()` and interpret it according
    /// to your command (e.g. PIN, SELECT, READ).
    pub fn status(&self) -> HealthCardResponseStatus {
        self.inner.sw().to_general_authenticate_status()
    }

    pub fn data(&self) -> Vec<u8> {
        self.inner.to_data()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
}

/// Error type returned by the foreign card channel implementation.
///
/// Foreign code should return:
/// - `Transport` for I/O or transport-level problems (reader errors, timeouts, etc.)
/// - `Apdu` for parsing/validation problems when building a `ResponseApdu`
#[derive(Debug, Clone, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum CardChannelError {
    /// Transport/reader error.
    ///
    /// `code` is an implementation-defined numeric error code (e.g. a platform/reader API error)
    /// and may be `0` if no specific code is available.
    #[error("{reason} (code {code})")]
    Transport { code: u32, reason: String },
    /// Invalid response APDU.
    #[error("apdu error: {error}")]
    Apdu { error: ApduError },
}

impl From<ApduError> for CardChannelError {
    fn from(err: ApduError) -> Self {
        CardChannelError::Apdu { error: err }
    }
}

/// Foreign card channel interface.
///
/// Implementations of this trait are provided by the foreign language runtime (e.g. Kotlin/Swift)
/// and passed into exported functions and objects as `session: Arc<dyn CardChannel>`.
///
/// Notes:
/// - `transmit` is modeled as taking `&self` for UniFFI compatibility.
/// - Internally, calls are serialized (see `FfiCardChannelAdapter`) to provide the core library
///   with the expected `&mut` access semantics.
#[uniffi::export(with_foreign)]
pub trait CardChannel: Send + Sync {
    /// Whether the underlying reader/session supports extended-length APDUs.
    ///
    /// Returning `false` forces the library to use short-length encoding, which may prevent
    /// certain commands from being sent if they exceed short-length limits.
    fn supports_extended_length(&self) -> bool;

    /// Transmits `command` to the card and returns the raw response APDU.
    ///
    /// The returned `ResponseApdu` must include the status word (SW1SW2).
    fn transmit(&self, command: Arc<CommandApdu>) -> Result<Arc<ResponseApdu>, CardChannelError>;
}

/// Adapter that turns the foreign `CardChannel` (which uses `&self`) into the core channel trait
/// (which uses `&mut self`).
///
/// The mutex serializes calls across threads and also ensures that higher-level exchanges that
/// rely on sequential APDU execution cannot interleave.
pub(crate) struct FfiCardChannelAdapter {
    inner: Arc<dyn CardChannel>,
    serialize: Mutex<()>,
}

impl FfiCardChannelAdapter {
    pub(crate) fn new(inner: Arc<dyn CardChannel>) -> Self {
        Self { inner, serialize: Mutex::new(()) }
    }
}

impl CoreCardChannel for FfiCardChannelAdapter {
    type Error = CardChannelError;

    fn supports_extended_length(&self) -> bool {
        let _guard = self.serialize.lock().unwrap_or_else(|err| err.into_inner());
        self.inner.supports_extended_length()
    }

    fn transmit(&mut self, command: &CardCommandApdu) -> Result<CardResponseApdu, Self::Error> {
        let _guard = self
            .serialize
            .lock()
            .map_err(|_| CardChannelError::Transport { code: 0, reason: "card channel lock poisoned".into() })?;
        let response = self.inner.transmit(CommandApdu::from_core(command.clone()))?;
        CardResponseApdu::try_from(response.as_ref()).map_err(CardChannelError::from)
    }
}

impl From<CardChannelError> for ExchangeError {
    fn from(err: CardChannelError) -> Self {
        match err {
            CardChannelError::Transport { code, reason } => ExchangeError::Transport { code, message: reason },
            CardChannelError::Apdu { error } => ExchangeError::Apdu(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::apdu::{CardCommandApdu, EXPECTED_LENGTH_WILDCARD_EXTENDED};

    #[test]
    fn command_apdu_roundtrip() {
        let ffi_apdu = CommandApdu::header_only(0x00, 0xA4, 0x04, 0x00).unwrap();
        let rebuilt = ffi_apdu.to_core();
        assert_eq!(rebuilt.to_bytes(), CardCommandApdu::header_only(0x00, 0xA4, 0x04, 0x00).unwrap().to_bytes());
    }

    #[test]
    fn command_apdu_validation_surfaces_error() {
        let err = CommandApdu::with_expect(
            0,
            0,
            0,
            0,
            crate::command::apdu::LengthClass::Short,
            (EXPECTED_LENGTH_WILDCARD_EXTENDED as u32) + 1,
        )
        .unwrap_err();
        assert!(matches!(err, ApduError::InvalidLength(_)));
    }

    #[test]
    fn response_apdu_conversion_preserves_bytes() {
        let response = CardResponseApdu::new(&[0xDE, 0xAD, 0x90, 0x00]).unwrap();
        let ffi_apdu = ResponseApdu::from_core(response.clone());
        let rebuilt = CardResponseApdu::try_from(ffi_apdu.as_ref()).unwrap();
        assert_eq!(rebuilt.to_bytes(), response.to_bytes());
        assert_eq!(ffi_apdu.status(), HealthCardResponseStatus::from_general_authenticate_status(0x9000));
    }

    #[test]
    fn response_apdu_from_bytes_roundtrip() {
        let ffi_apdu = ResponseApdu::from_bytes(vec![0xDE, 0xAD, 0x90, 0x00]).unwrap();
        assert_eq!(ffi_apdu.sw(), 0x9000);
        assert_eq!(ffi_apdu.data(), vec![0xDE, 0xAD]);
        assert_eq!(ffi_apdu.to_bytes(), vec![0xDE, 0xAD, 0x90, 0x00]);
    }
}
