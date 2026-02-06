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

use std::borrow::Cow;

use thiserror::Error;

pub type Asn1DecoderResult<T> = Result<T, Asn1DecoderError>;
pub type Asn1EncoderResult<T> = Result<T, Asn1EncoderError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asn1TimeType {
    Utc,
    Generalized,
}

#[derive(Debug, Error, Clone)]
pub enum Asn1DecoderError {
    #[error("Expected tag `{expected}` but got `{actual}`")]
    UnexpectedTag { expected: String, actual: String },
    #[error("Unparsed bytes remaining")]
    UnparsedBytesRemaining,
    #[error("Infinite length object must be finished with `0x00 0x00`")]
    MissingEndOfContentMarker,
    #[error("Unexpected end of data while {context}")]
    UnexpectedEndOfData { context: &'static str },
    #[error("Integer overflow computing {context}")]
    IntegerOverflow { context: &'static str },
    #[error("Length must be in range of [1, 4]. Is `{length}`")]
    InvalidLength { length: usize },
    #[error("Skip exceeds available data")]
    SkipExceedsAvailableData,
    #[error("Can't skip bytes inside infinite length object")]
    SkipInsideInfiniteLengthObject,
    #[error("Invalid unused bit count: {count}")]
    InvalidUnusedBitCount { count: i32 },
    #[error("BIT STRING content is empty but indicates unused bits")]
    BitStringIndicatesUnusedBits,
    #[error("Malformed UTF-8 string")]
    MalformedUtf8String,
    #[error("Encoded OID cannot be empty")]
    EmptyObjectIdentifier,
    #[error("Invalid OID encoding: unfinished encoding")]
    UnfinishedObjectIdentifierEncoding,
    #[error("Malformed UTC_TIME (non-UTF8)")]
    MalformedUtcTimeEncoding,
    #[error("Malformed GENERALIZED_TIME (non-UTF8)")]
    MalformedGeneralizedTimeEncoding,
    #[error("Invalid {context}: `{value}`")]
    InvalidTimeValue { context: &'static str, value: String },
    #[error("Certificate date digit {index} must be 0..9")]
    InvalidCertificateDateDigit { index: usize },
    #[error("Certificate month must be 1..=12 (got {month})")]
    InvalidCertificateMonth { month: u8 },
    #[error("Certificate day must be 1..=31 (got {day})")]
    InvalidCertificateDay { day: u8 },
    #[error("{message}")]
    Custom { message: Cow<'static, str> },
}

impl Asn1DecoderError {
    pub fn custom(message: impl Into<Cow<'static, str>>) -> Self {
        Self::Custom { message: message.into() }
    }

    pub fn unexpected_end_of_data(context: &'static str) -> Self {
        Self::UnexpectedEndOfData { context }
    }

    pub fn integer_overflow(context: &'static str) -> Self {
        Self::IntegerOverflow { context }
    }

    pub fn invalid_time_value(context: &'static str, value: impl Into<String>) -> Self {
        Self::InvalidTimeValue { context, value: value.into() }
    }
}

impl From<&'static str> for Asn1DecoderError {
    fn from(value: &'static str) -> Self {
        Self::Custom { message: Cow::from(value) }
    }
}

impl From<String> for Asn1DecoderError {
    fn from(value: String) -> Self {
        Self::Custom { message: Cow::from(value) }
    }
}

#[derive(Debug, Error, Clone)]
pub enum Asn1EncoderError {
    #[error("Invalid unused bit count: {count}")]
    InvalidUnusedBitCount { count: u8 },
    #[error("Invalid OID part: {value}")]
    InvalidObjectIdentifierPart { value: String },
    #[error("OID must have at least two components")]
    ObjectIdentifierMissingComponents,
    #[error("OID first part must be 0, 1, or 2 (got {value})")]
    InvalidObjectIdentifierFirstComponent { value: i32 },
    #[error("OID second part must be 0-39 for first part 0 or 1 (got {value})")]
    InvalidObjectIdentifierSecondComponent { value: i32 },
    #[error("Expected {expected:?} time but got {actual:?} time")]
    TimeTypeMismatch { expected: Asn1TimeType, actual: Asn1TimeType },
    #[error("{message}")]
    Custom { message: Cow<'static, str> },
}

impl Asn1EncoderError {
    pub fn custom(message: impl Into<Cow<'static, str>>) -> Self {
        Self::Custom { message: message.into() }
    }

    pub fn invalid_unused_bit_count(count: u8) -> Self {
        Self::InvalidUnusedBitCount { count }
    }

    pub fn invalid_object_identifier_part(value: impl Into<String>) -> Self {
        Self::InvalidObjectIdentifierPart { value: value.into() }
    }

    pub fn object_identifier_missing_components() -> Self {
        Self::ObjectIdentifierMissingComponents
    }

    pub fn invalid_object_identifier_first_component(value: i32) -> Self {
        Self::InvalidObjectIdentifierFirstComponent { value }
    }

    pub fn invalid_object_identifier_second_component(value: i32) -> Self {
        Self::InvalidObjectIdentifierSecondComponent { value }
    }
}

impl From<&'static str> for Asn1EncoderError {
    fn from(value: &'static str) -> Self {
        Self::custom(value)
    }
}

impl From<String> for Asn1EncoderError {
    fn from(value: String) -> Self {
        Self::custom(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encoder_custom_preserves_message() {
        let err = Asn1EncoderError::custom("custom-message");
        assert!(matches!(
            err,
            Asn1EncoderError::Custom { message } if message == "custom-message"
        ));
    }
}
