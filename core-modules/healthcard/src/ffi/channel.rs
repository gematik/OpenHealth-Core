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

use crate::command::apdu::{ApduError, CardCommandApdu, CardResponseApdu};
use crate::command::health_card_status::{HealthCardResponseStatus, StatusWordExt};
use crate::exchange::ExchangeError;
use std::sync::Arc;
use thiserror::Error;

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
    #[uniffi::constructor]
    pub fn header_only(cla: u8, ins: u8, p1: u8, p2: u8) -> Result<Self, ApduError> {
        Ok(Self { inner: CardCommandApdu::header_only(cla, ins, p1, p2)? })
    }

    #[uniffi::constructor]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ApduError> {
        Ok(Self { inner: CardCommandApdu::from_bytes(&bytes)? })
    }

    #[uniffi::constructor]
    pub fn with_expect(
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        length_class: crate::command::apdu::LengthClass,
        expected_length: u32,
    ) -> Result<Self, ApduError> {
        Ok(Self { inner: CardCommandApdu::with_expect(cla, ins, p1, p2, length_class, expected_length as usize)? })
    }

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
        Ok(Self {
            inner: CardCommandApdu::with_data_and_expect(
                cla,
                ins,
                p1,
                p2,
                length_class,
                data,
                expected_length as usize,
            )?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes()
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct ResponseApdu {
    pub sw: u16,
    pub status: HealthCardResponseStatus,
    pub data: Vec<u8>,
}

impl From<CardResponseApdu> for ResponseApdu {
    fn from(response: CardResponseApdu) -> Self {
        let sw = response.sw();
        ResponseApdu { sw, status: sw.to_general_authenticate_status(), data: response.to_data() }
    }
}

impl TryFrom<ResponseApdu> for CardResponseApdu {
    type Error = ApduError;

    fn try_from(response: ResponseApdu) -> Result<Self, Self::Error> {
        let mut full = response.data;
        full.push((response.sw >> 8) as u8);
        full.push(response.sw as u8);
        CardResponseApdu::new(&full)
    }
}

/// Error type returned by the foreign card channel implementation.
#[derive(Debug, Clone, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum CardChannelError {
    #[error("{reason} (code {code})")]
    Transport { code: u32, reason: String },
    #[error("apdu error: {error}")]
    Apdu { error: ApduError },
}

impl From<ApduError> for CardChannelError {
    fn from(err: ApduError) -> Self {
        CardChannelError::Apdu { error: err }
    }
}

#[uniffi::export(with_foreign)]
pub trait CardChannel: Send + Sync {
    fn supports_extended_length(&self) -> bool;

    fn transmit(&self, command: Arc<CommandApdu>) -> Result<ResponseApdu, CardChannelError>;
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
        let ffi_apdu = ResponseApdu::from(response.clone());
        let rebuilt = CardResponseApdu::try_from(ffi_apdu.clone()).unwrap();
        assert_eq!(rebuilt.to_bytes(), response.to_bytes());
        assert_eq!(ffi_apdu.status, HealthCardResponseStatus::from_general_authenticate_status(0x9000));
    }
}
