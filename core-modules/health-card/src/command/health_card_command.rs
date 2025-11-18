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

use std::collections::HashMap;
use std::fmt;

use thiserror::Error;

use crate::command::apdu::{ApduError, CardCommandApdu, CardResponseApdu};
use crate::command::apdu::{EXPECTED_LENGTH_WILDCARD_EXTENDED, EXPECTED_LENGTH_WILDCARD_SHORT};
use crate::command::health_card_status::HealthCardResponseStatus;

/// Special value to indicate that all available data should be expected.
pub const EXPECT_ALL_WILDCARD: i32 = -1;

/// Superclass for all health health-card commands.
#[derive(Clone)]
pub struct HealthCardCommand {
    /// Expected status codes mapped to their response status
    pub expected_status: HashMap<u16, HealthCardResponseStatus>,
    /// The class byte (CLA)
    pub cla: u8,
    /// The instruction byte (INS)
    pub ins: u8,
    /// The parameter 1 byte (P1)
    pub p1: u8,
    /// The parameter 2 byte (P2)
    pub p2: u8,
    /// The command data
    pub data: Option<Vec<u8>>,
    /// The expected response length
    pub ne: Option<usize>,
}

impl HealthCardCommand {
    /// Creates a new HealthCardCommand.
    ///
    /// # Arguments
    /// * `expected_status` - Map of expected status words to their corresponding HealthCardResponseStatus
    /// * `cla` - Class byte
    /// * `ins` - Instruction byte
    /// * `p1` - Parameter 1 byte
    /// * `p2` - Parameter 2 byte
    /// * `data` - Optional command data
    /// * `ne` - Optional expected response length
    pub fn new(
        expected_status: HashMap<u16, HealthCardResponseStatus>,
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: Option<Vec<u8>>,
        ne: Option<i32>,
    ) -> Self {
        let ne_usize = ne.map(|n| if n >= 0 { n as usize } else { 0 });

        HealthCardCommand { expected_status, cla, ins, p1, p2, data, ne: ne_usize }
    }

    /// Converts the HealthCardCommand to a CardCommandApdu.
    ///
    /// # Arguments
    /// * `scope_supports_extended_length` - Indicates if the scope supports extended length
    pub fn command_apdu(&self, scope_supports_extended_length: bool) -> Result<CardCommandApdu, ApduError> {
        let expected_length = match self.ne {
            Some(ne) if ne == EXPECT_ALL_WILDCARD as usize => {
                if scope_supports_extended_length {
                    Some(EXPECTED_LENGTH_WILDCARD_EXTENDED)
                } else {
                    Some(EXPECTED_LENGTH_WILDCARD_SHORT)
                }
            }
            other => other,
        };

        CardCommandApdu::new(self.cla, self.ins, self.p1, self.p2, self.data.clone(), expected_length)
    }
}

impl fmt::Debug for HealthCardCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HealthCardCommand")
            .field("cla", &format!("0x{:02X}", self.cla))
            .field("ins", &format!("0x{:02X}", self.ins))
            .field("p1", &format!("0x{:02X}", self.p1))
            .field("p2", &format!("0x{:02X}", self.p2))
            .field("data", &self.data)
            .field("ne", &self.ne)
            .field("expected_status", &self.expected_status.len())
            .finish()
    }
}

/// Represents the response from a HealthCardCommand.
#[derive(Debug, Clone)]
pub struct HealthCardResponse {
    /// The status of the command execution
    pub status: HealthCardResponseStatus,
    /// The raw response APDU
    pub apdu: CardResponseApdu,
}

impl HealthCardResponse {
    /// Creates a new HealthCardResponse.
    ///
    /// # Arguments
    /// * `status` - The status of the command execution
    /// * `apdu` - The raw response APDU
    pub fn new(status: HealthCardResponseStatus, apdu: CardResponseApdu) -> Self {
        HealthCardResponse { status, apdu }
    }

    /// Checks if the command execution was successful.
    pub fn require_success(&self) -> Result<(), ResponseException> {
        if self.status != HealthCardResponseStatus::Success {
            Err(ResponseException::new(self.status))
        } else {
            Ok(())
        }
    }
}

/// Exception thrown when a command execution was not successful.
#[derive(Debug, Clone, Error)]
#[error("{health_card_response_status}")]
pub struct ResponseException {
    /// The status indicating the reason for the failure
    pub health_card_response_status: HealthCardResponseStatus,
}

impl ResponseException {
    /// Creates a new ResponseException.
    ///
    /// # Arguments
    /// * `health_card_response_status` - The status indicating the reason for the failure
    pub fn new(health_card_response_status: HealthCardResponseStatus) -> Self {
        ResponseException { health_card_response_status }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_health_card_command_creation() {
        let mut expected_status = HashMap::new();
        expected_status.insert(0x9000, HealthCardResponseStatus::Success);

        let command =
            HealthCardCommand::new(expected_status, 0x00, 0xA4, 0x04, 0x00, Some(vec![0x3F, 0x00]), Some(256));

        assert_eq!(command.cla, 0x00);
        assert_eq!(command.ins, 0xA4);
        assert_eq!(command.p1, 0x04);
        assert_eq!(command.p2, 0x00);
        assert_eq!(command.data, Some(vec![0x3F, 0x00]));
        assert_eq!(command.ne, Some(256));
    }

    #[test]
    fn test_health_card_response() {
        let apdu_data = vec![0x90, 0x00];
        let response_apdu = CardResponseApdu::new(&apdu_data).unwrap();
        let response = HealthCardResponse::new(HealthCardResponseStatus::Success, response_apdu.clone());

        assert!(response.require_success().is_ok());

        let failed_response = HealthCardResponse::new(HealthCardResponseStatus::FileNotFound, response_apdu);

        let result = failed_response.require_success();
        assert!(result.is_err());
        if let Err(e) = result {
            assert_eq!(e.health_card_response_status, HealthCardResponseStatus::FileNotFound);
        }
    }
}
