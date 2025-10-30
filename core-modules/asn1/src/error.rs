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

pub type DecoderResult<T> = Result<T, DecoderError>;
pub type EncoderResult<T> = Result<T, EncoderError>;

#[derive(Debug, Error, Clone)]
pub enum DecoderError {
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
    #[error("{message}")]
    Custom { message: Cow<'static, str> },
}

impl DecoderError {
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

impl From<&'static str> for DecoderError {
    fn from(value: &'static str) -> Self {
        Self::Custom { message: Cow::from(value) }
    }
}

impl From<String> for DecoderError {
    fn from(value: String) -> Self {
        Self::Custom { message: Cow::from(value) }
    }
}

#[derive(Debug, Error, Clone)]
#[error("{message}")]
pub struct EncoderError {
    message: Cow<'static, str>,
}

impl EncoderError {
    pub fn new(message: impl Into<Cow<'static, str>>) -> Self {
        Self { message: message.into() }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

impl From<&'static str> for EncoderError {
    fn from(value: &'static str) -> Self {
        Self::new(value)
    }
}

impl From<String> for EncoderError {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}
