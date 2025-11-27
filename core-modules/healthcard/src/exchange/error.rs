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

use super::pace_info::PaceInfoError;
use crate::asn1::error::Asn1DecoderError;
use crate::card::encrypted_pin_format2::PinBlockError;
use crate::command::apdu::ApduError;
use crate::command::general_authenticate_command::GeneralAuthenticateCommandError;
use crate::command::health_card_status::HealthCardResponseStatus;
use crate::command::manage_security_environment_command::ManageSecurityEnvironmentCommandError;
use crate::command::CommandError;
use asn1::error::Asn1EncoderError;
use crypto::error::CryptoError;
use thiserror::Error;

/// Error type for higher-level healthcard exchanges.
#[derive(Debug, Error)]
pub enum ExchangeError {
    /// Transport layer failure while transmitting an APDU.
    #[error("{message} (code {code})")]
    Transport { code: u32, message: String },
    #[error("APDU error: {0}")]
    Apdu(#[from] ApduError),
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
    /// Error originating from ASN.1 parsing.
    #[error("ASN.1 error: {0}")]
    Asn1DecoderError(#[from] Asn1DecoderError),
    /// Error originating from ASN.1 encoding.
    #[error("ASN.1 error: {0}")]
    Asn1EncoderError(#[from] Asn1EncoderError),
    /// Error originating from GENERAL AUTHENTICATE command construction.
    #[error("GENERAL AUTHENTICATE command error: {0}")]
    GeneralAuthenticateCommand(#[from] GeneralAuthenticateCommandError),
    /// Error originating from MANAGE SECURITY ENVIRONMENT command construction.
    #[error("MANAGE SECURITY ENVIRONMENT command error: {0}")]
    ManageSecurityEnvironmentCommand(#[from] ManageSecurityEnvironmentCommandError),
    /// Error while composing a command prior to transmission.
    #[error("command composition error: {0}")]
    Command(#[from] CommandError),
    /// Failed to construct a PIN block from caller input.
    #[error("pin block error: {0}")]
    PinBlock(#[from] PinBlockError),
    /// Card version did not meet the required baseline (e.g. not eGK v2.1).
    #[error("unsupported healthcard version")]
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
}
