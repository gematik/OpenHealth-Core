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

use crate::ossl::api::OsslError;
use asn1::error::Asn1DecoderError;
use asn1::error::Asn1EncoderError;

/// Errors returned by high-level cryptographic operations.
#[derive(Debug, thiserror::Error)]
// #[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum CryptoError {
    /// The caller attempted to finalize a cipher twice.
    #[error("cipher finalized twice")]
    FinalizedTwice,
    /// An input or parameter was invalid, with context.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// An elliptic curve point was invalid or malformed.
    #[error("invalid ec point: {0}")]
    InvalidEcPoint(String),
    /// Underlying native cryptographic failure with original message.
    #[error("native error: {0}")]
    Native(String),
    /// Error originating from ASN.1 parsing.
    #[error("ASN.1 error: {0}")]
    Asn1Decoding(#[from] Asn1DecoderError),
    /// Error originating from ASN.1 encoding.
    #[error("ASN.1 error: {0}")]
    Asn1Encoding(#[from] Asn1EncoderError),
}

impl From<OsslError> for CryptoError {
    fn from(e: OsslError) -> Self {
        CryptoError::Native(e.to_string())
    }
}

/// Convenient result alias used throughout this crate.
pub type CryptoResult<T> = Result<T, CryptoError>;
