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
use crate::exchange::channel::CardChannel as CoreCardChannel;
use crate::exchange::ExchangeError;
use crate::ffi::maybe_zeroizing_vec::VecOfU8 as FfiVecOfU8;
use openhealth_asn1::maybe_zeroizing_vec::VecOfU8 as Asn1VecOfU8;
use std::sync::{Arc, Mutex};
use thiserror::Error;

/// ISO/IEC 7816-4 command APDU.
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

fn u8_from_i32(name: &str, value: i32) -> Result<u8, ApduError> {
    u8::try_from(value)
        .map_err(|_| ApduError::InvalidLength(format!("{name} must be in range [0, {}]: {value}", u8::MAX)))
}

fn u16_from_i32(name: &str, value: i32) -> Result<u16, ApduError> {
    u16::try_from(value)
        .map_err(|_| ApduError::InvalidLength(format!("{name} must be in range [0, {}]: {value}", u16::MAX)))
}

fn usize_from_i32(name: &str, value: i32) -> Result<usize, ApduError> {
    usize::try_from(value).map_err(|_| ApduError::InvalidLength(format!("{name} must not be negative: {value}")))
}

#[uniffi::export]
impl CommandApdu {
    /// Creates a case 1 APDU (header only, no data, no expected length).
    #[uniffi::constructor]
    pub fn header_only(cla: i32, ins: i32, p1: i32, p2: i32) -> Result<Self, ApduError> {
        let cla = u8_from_i32("cla", cla)?;
        let ins = u8_from_i32("ins", ins)?;
        let p1 = u8_from_i32("p1", p1)?;
        let p2 = u8_from_i32("p2", p2)?;
        Ok(Self { inner: CardCommandApdu::header_only(cla, ins, p1, p2)? })
    }

    /// Parses a command APDU from raw bytes.
    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ApduError> {
        Ok(Self { inner: CardCommandApdu::from_bytes(&bytes)? })
    }

    /// Creates an APDU with an expected response length (`Le`).
    ///
    /// `expected_length` is the expected number of response bytes (excluding SW1SW2).
    ///
    /// Special values:
    /// - With `length_class = Short`, `expected_length` must be in `0..=256`.
    ///   - `expected_length = 0` or `256` requests the maximum short-length response (`Le = 0x00`).
    /// - With `length_class = Extended`, `expected_length` must be in `257..=65536`.
    ///   - `expected_length = 65536` requests the maximum extended-length response (`Le = 0x0000`).
    #[uniffi::constructor]
    pub fn with_expect(
        cla: i32,
        ins: i32,
        p1: i32,
        p2: i32,
        length_class: crate::command::apdu::LengthClass,
        expected_length: i32,
    ) -> Result<Self, ApduError> {
        let cla = u8_from_i32("cla", cla)?;
        let ins = u8_from_i32("ins", ins)?;
        let p1 = u8_from_i32("p1", p1)?;
        let p2 = u8_from_i32("p2", p2)?;
        let expected_length = usize_from_i32("expected_length", expected_length)?;
        Ok(Self { inner: CardCommandApdu::with_expect(cla, ins, p1, p2, length_class, expected_length)? })
    }

    /// Creates an APDU with command data (`Lc` + data), without an expected response length.
    ///
    /// `length_class` selects short or extended-length encoding and therefore constrains `data`
    /// length (short: `1..=255`, extended: `>= 256`).
    #[uniffi::constructor]
    pub fn with_data(
        cla: i32,
        ins: i32,
        p1: i32,
        p2: i32,
        length_class: crate::command::apdu::LengthClass,
        data: Vec<u8>,
    ) -> Result<Self, ApduError> {
        let cla = u8_from_i32("cla", cla)?;
        let ins = u8_from_i32("ins", ins)?;
        let p1 = u8_from_i32("p1", p1)?;
        let p2 = u8_from_i32("p2", p2)?;
        Ok(Self {
            inner: CardCommandApdu::with_data(cla, ins, p1, p2, length_class, Asn1VecOfU8::new_zeroizing(data))?,
        })
    }

    /// Creates an APDU with command data (`Lc` + data) and an expected response length (`Le`).
    ///
    /// See `with_expect` for the valid `expected_length` ranges.
    #[uniffi::constructor]
    pub fn with_data_and_expect(
        cla: i32,
        ins: i32,
        p1: i32,
        p2: i32,
        length_class: crate::command::apdu::LengthClass,
        data: Vec<u8>,
        expected_length: i32,
    ) -> Result<Self, ApduError> {
        let cla = u8_from_i32("cla", cla)?;
        let ins = u8_from_i32("ins", ins)?;
        let p1 = u8_from_i32("p1", p1)?;
        let p2 = u8_from_i32("p2", p2)?;
        let expected_length = usize_from_i32("expected_length", expected_length)?;
        Ok(Self {
            inner: CardCommandApdu::with_data_and_expect(
                cla,
                ins,
                p1,
                p2,
                length_class,
                Asn1VecOfU8::new_zeroizing(data),
                expected_length,
            )?,
        })
    }

    pub fn to_vec(&self) -> Arc<FfiVecOfU8> {
        FfiVecOfU8::from_core(self.inner.to_vec())
    }
}

/// ISO/IEC 7816-4 response APDU.
///
/// This object represents a response APDU and exposes:
/// - `sw()`: status word (SW1SW2)
/// - `data()`: response data without the status word
/// - `to_vec()`: raw APDU bytes (`data || SW1 || SW2`)
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
    /// The input must contain at least SW1SW2 (2 bytes).
    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ApduError> {
        Ok(ResponseApdu { inner: CardResponseApdu::from_bytes(&bytes)? })
    }

    /// Creates a response APDU from `sw` (SW1SW2) and response `data`.
    ///
    /// `sw` is interpreted as big-endian (SW1<<8 | SW2).
    #[uniffi::constructor]
    pub fn from_parts(sw: i32, data: Vec<u8>) -> Result<Self, ApduError> {
        let sw = u16_from_i32("sw", sw)?;
        let mut full = data;
        full.push((sw >> 8) as u8);
        full.push(sw as u8);
        Ok(ResponseApdu { inner: CardResponseApdu::new_nonzeroizing(&full)? })
    }

    /// Returns the status word (SW1SW2) as `0xSW1SW2` (big-endian).
    pub fn sw(&self) -> i32 {
        i32::from(self.inner.sw())
    }

    /// Returns the response data (without SW1SW2).
    pub fn data(&self) -> Vec<u8> {
        self.inner.to_data()
    }

    /// Serializes the response APDU to raw bytes (`data || SW1 || SW2`).
    pub fn to_vec(&self) -> Arc<FfiVecOfU8> {
        FfiVecOfU8::from_core(self.inner.to_vec())
    }
}

/// Error type returned by a `CardChannel` implementation.
///
/// - Use `Transport` for I/O or reader/transport-level problems (timeouts, disconnected card, ...).
/// - Use `Apdu` if a response was received but it is not a valid response APDU.
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

/// Card channel interface to be implemented by the host application.
///
/// A `CardChannel` represents an established connection/session to a smart card reader and is the
/// transport layer used by this library to exchange APDUs with the card.
///
/// Implementations must be thread-safe (`Send + Sync`). Calls from this library are serialized,
/// but they may come from different threads.
#[uniffi::export(with_foreign)]
pub trait CardChannel: Send + Sync {
    /// Whether the underlying reader/session supports extended-length APDUs.
    ///
    /// Returning `false` forces the library to use short-length encoding, which may prevent
    /// certain commands from being sent if they exceed short-length limits.
    fn supports_extended_length(&self) -> bool;

    /// Transmits `command` to the card and returns the response APDU.
    ///
    /// The returned `ResponseApdu` must include the status word (SW1SW2). If the reader API
    /// returns raw bytes, use `ResponseApdu::from_bytes`.
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
    use crate::ffi::maybe_zeroizing_vec::VecOfU8 as FfiVecOfU8;

    #[test]
    fn u8_from_i32_rejects_negative_values() {
        let err = u8_from_i32("cla", -1).unwrap_err();
        assert!(matches!(err, ApduError::InvalidLength(_)));
    }

    #[test]
    fn usize_from_i32_rejects_negative_values() {
        let err = usize_from_i32("expected_length", -1).unwrap_err();
        assert!(matches!(err, ApduError::InvalidLength(_)));
    }

    #[test]
    fn command_apdu_roundtrip() {
        let ffi_apdu = CommandApdu::header_only(0x00, 0xA4, 0x04, 0x00).unwrap();
        let rebuilt = ffi_apdu.to_core();
        assert_eq!(rebuilt.to_vec(), CardCommandApdu::header_only(0x00, 0xA4, 0x04, 0x00).unwrap().to_vec());
    }

    #[test]
    fn command_apdu_validation_surfaces_error() {
        let err = CommandApdu::with_expect(
            0,
            0,
            0,
            0,
            crate::command::apdu::LengthClass::Short,
            (EXPECTED_LENGTH_WILDCARD_EXTENDED as i32) + 1,
        )
        .unwrap_err();
        assert!(matches!(err, ApduError::InvalidLength(_)));
    }

    #[test]
    fn response_apdu_conversion_preserves_bytes() {
        let response = CardResponseApdu::new_nonzeroizing(&[0xDE, 0xAD, 0x90, 0x00]).unwrap();
        let ffi_apdu = ResponseApdu::from_core(response.clone());
        let rebuilt = CardResponseApdu::try_from(ffi_apdu.as_ref()).unwrap();
        assert_eq!(rebuilt.to_vec(), response.to_vec());
        assert_eq!(ffi_apdu.sw(), 0x9000);
    }

    #[test]
    fn response_apdu_from_bytes_roundtrip() {
        let ffi_apdu = ResponseApdu::from_bytes(vec![0xDE, 0xAD, 0x90, 0x00]).unwrap();
        assert_eq!(ffi_apdu.sw(), 0x9000);
        assert_eq!(ffi_apdu.data(), vec![0xDE, 0xAD]);
        assert_eq!(ffi_apdu.to_vec(), FfiVecOfU8::from_nonzeroizing_bytes(vec![0xDE, 0xAD, 0x90, 0x00]));
    }

    #[test]
    fn response_apdu_from_parts_roundtrip() {
        let response = ResponseApdu::from_parts(0x9000, vec![0xDE, 0xAD]).unwrap();
        assert_eq!(response.sw(), 0x9000);
        assert_eq!(response.data(), vec![0xDE, 0xAD]);
        assert_eq!(response.to_vec(), FfiVecOfU8::from_nonzeroizing_bytes(vec![0xDE, 0xAD, 0x90, 0x00]));
    }

    #[test]
    fn apdu_error_converts_to_channel_error() {
        let err = ApduError::InvalidLength("oops".to_string());
        let converted: CardChannelError = err.clone().into();
        assert!(matches!(converted, CardChannelError::Apdu { error: ApduError::InvalidLength(_) }));
    }

    #[test]
    fn command_apdu_with_data_and_expect_rejects_large_length() {
        let err = CommandApdu::with_data_and_expect(
            0,
            0,
            0,
            0,
            crate::command::apdu::LengthClass::Short,
            vec![0x01],
            i32::MAX,
        )
        .unwrap_err();
        assert!(matches!(err, ApduError::InvalidLength(_)));
    }
}
