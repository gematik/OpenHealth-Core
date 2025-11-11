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

use super::error::ExchangeError;
use crate::command::apdu::{CardCommandApdu, CardResponseApdu};
use crate::command::health_card_command::{HealthCardCommand, HealthCardResponse};
use crate::command::health_card_status::HealthCardResponseStatus;

/// Trait implemented by a low-level card transport.
///
/// The transport is responsible for converting a [CardCommandApdu] into a
/// [CardResponseApdu]. Higher-level logic (secure messaging, status mapping)
/// lives in the exchange layer.
pub trait CardSession {
    /// Concrete error type returned by the transport.
    /// It must be convertible into `ExchangeError` so higher layers
    /// can normalize error handling without exposing backend details.
    type Error: Into<ExchangeError>;
    /// Return true if the underlying channel supports extended length APDUs.
    fn supports_extended_length(&self) -> bool;

    /// Transmit a command APDU to the card and return the raw response.
    fn transmit(&mut self, command: &CardCommandApdu) -> Result<CardResponseApdu, Self::Error>;
}

/// Extension trait providing convenience helpers on top of [CardSession].
pub trait CardSessionExt: CardSession {
    /// Encode and transmit a [HealthCardCommand], returning the mapped response.
    fn execute_command(&mut self, command: &HealthCardCommand) -> Result<HealthCardResponse, ExchangeError> {
        let apdu = command.command_apdu(self.supports_extended_length()).map_err(ExchangeError::apdu)?;

        let response = self.transmit(&apdu).map_err(Into::into)?;

        let status =
            command.expected_status.get(&response.sw()).copied().unwrap_or(HealthCardResponseStatus::UnknownStatus);

        Ok(HealthCardResponse::new(status, response))
    }

    /// Execute a command and assert that the response indicates success.
    fn execute_command_success(&mut self, command: &HealthCardCommand) -> Result<HealthCardResponse, ExchangeError> {
        let response = self.execute_command(command)?;
        if response.status.is_success() {
            Ok(response)
        } else {
            Err(ExchangeError::unexpected(response.status))
        }
    }
}

impl<T: CardSession + ?Sized> CardSessionExt for T {}
