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

use crate::asn1::error::Asn1DecoderError;
use crate::command::health_card_status::HealthCardResponseStatus;
use crypto::error::CryptoError;
use std::error::Error;
use thiserror::Error;

use super::pace_info::PaceInfoError;

/// Error type for higher-level health-card exchanges.
#[derive(Debug, Error)]
pub enum ExchangeError {
    /// Transport layer failure while transmitting an APDU.
    #[error("transport error: {0}")]
    Transport(#[source] Box<dyn Error + Send + Sync>),
    /// Failed to encode an APDU before transmission.
    #[error("apdu encoding error: {0}")]
    Apdu(String),
    /// Card returned a status that does not satisfy the requested operation.
    #[error("unexpected card status: {status}")]
    UnexpectedStatus { status: HealthCardResponseStatus },
    /// Card returned a specific status that is bubbled up to the caller.
    #[error("card reported status: {0}")]
    Status(HealthCardResponseStatus),
    /// Error while parsing PACE information.
    #[error("PACE info error: {0}")]
    PaceInfo(#[from] PaceInfoError),
    /// Error originating from the cryptography module.
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    /// Error originating from ASN.1 parsing/encoding.
    #[error("ASN.1 error: {0}")]
    Asn1(#[from] Asn1DecoderError),
    /// Card version did not meet the required baseline (e.g. not eGK v2.1).
    #[error("unsupported health-card version")]
    InvalidCardVersion,
    /// Caller supplied invalid arguments (e.g. missing new PIN for a change operation).
    #[error("invalid argument: {0}")]
    InvalidArgument(&'static str),
    /// Mutual authentication during PACE failed (MAC mismatch).
    #[error("mutual authentication failed")]
    MutualAuthenticationFailed,
}

impl ExchangeError {
    pub fn unexpected(status: HealthCardResponseStatus) -> Self {
        ExchangeError::UnexpectedStatus { status }
    }

    pub fn status(status: HealthCardResponseStatus) -> Self {
        ExchangeError::Status(status)
    }

    pub fn apdu<E: Error>(err: E) -> Self {
        ExchangeError::Apdu(err.to_string())
    }
}
