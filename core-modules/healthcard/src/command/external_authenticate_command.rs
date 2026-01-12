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

use thiserror::Error;

use crate::command::apdu::EXPECTED_LENGTH_WILDCARD_SHORT;
use crate::command::health_card_command::{ExpectedLength, HealthCardCommand};
use crate::command::health_card_status::EXTERNAL_AUTHENTICATE_STATUS;

/// CLA byte for the EXTERNAL AUTHENTICATE command
const CLA: u8 = 0x00;
/// INS byte for the EXTERNAL AUTHENTICATE command
const INS: u8 = 0x82;
/// P1 and P2 parameter (no meaning)
const NO_MEANING: u8 = 0x00;

#[derive(Debug, Error)]
pub enum ExternalAuthenticateCommandError {
    #[error("EXTERNAL AUTHENTICATE command data length must be < {max}, got {length}")]
    CommandDataTooLong { length: usize, max: usize },
}

type ExternalAuthenticateResult<T> = Result<T, ExternalAuthenticateCommandError>;

/// Extension trait for HealthCardCommand to provide EXTERNAL AUTHENTICATE commands
pub trait ExternalAuthenticateCommand {
    /// Creates a HealthCardCommand for the EXTERNAL AUTHENTICATE command without response data.
    /// Use case: gemSpec_COS_3.14.0#14.7.1.1 (Case 3S).
    ///
    /// # Arguments
    /// * `cmd_data` - response token from the external instance.
    fn external_authenticate(cmd_data: &[u8]) -> ExternalAuthenticateResult<HealthCardCommand>;

    /// Creates a HealthCardCommand for the MUTUAL AUTHENTICATE command with response data.
    /// Use case: gemSpec_COS_3.14.0#14.7.1.2 (Case 4S, Le = WildCardShort).
    ///
    /// # Arguments
    /// * `cmd_data` - response token from the external instance.
    fn mutual_authenticate(cmd_data: &[u8]) -> ExternalAuthenticateResult<HealthCardCommand>;
}

impl ExternalAuthenticateCommand for HealthCardCommand {
    fn external_authenticate(cmd_data: &[u8]) -> ExternalAuthenticateResult<HealthCardCommand> {
        ensure_short_command_data(cmd_data)?;

        Ok(HealthCardCommand::new(
            EXTERNAL_AUTHENTICATE_STATUS.clone(),
            CLA,
            INS,
            NO_MEANING,
            NO_MEANING,
            Some(cmd_data.to_vec()),
            None,
        ))
    }

    fn mutual_authenticate(cmd_data: &[u8]) -> ExternalAuthenticateResult<HealthCardCommand> {
        ensure_short_command_data(cmd_data)?;

        Ok(HealthCardCommand::new(
            EXTERNAL_AUTHENTICATE_STATUS.clone(),
            CLA,
            INS,
            NO_MEANING,
            NO_MEANING,
            Some(cmd_data.to_vec()),
            Some(ExpectedLength::Exact(EXPECTED_LENGTH_WILDCARD_SHORT)),
        ))
    }
}

fn ensure_short_command_data(cmd_data: &[u8]) -> ExternalAuthenticateResult<()> {
    if cmd_data.len() >= EXPECTED_LENGTH_WILDCARD_SHORT {
        return Err(ExternalAuthenticateCommandError::CommandDataTooLong {
            length: cmd_data.len(),
            max: EXPECTED_LENGTH_WILDCARD_SHORT - 1,
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_external_authenticate_command() {
        let cmd_data = vec![0x01, 0x02, 0x03];
        let command = HealthCardCommand::external_authenticate(&cmd_data).unwrap();

        assert_eq!(command.cla, CLA);
        assert_eq!(command.ins, INS);
        assert_eq!(command.p1, NO_MEANING);
        assert_eq!(command.p2, NO_MEANING);
        assert_eq!(command.data, Some(cmd_data));
        assert_eq!(command.ne, None);
    }

    #[test]
    fn test_mutual_authenticate_command() {
        let cmd_data = vec![0xDE, 0xAD];
        let command = HealthCardCommand::mutual_authenticate(&cmd_data).unwrap();

        assert_eq!(command.cla, CLA);
        assert_eq!(command.ins, INS);
        assert_eq!(command.p1, NO_MEANING);
        assert_eq!(command.p2, NO_MEANING);
        assert_eq!(command.data, Some(cmd_data));
        assert_eq!(command.ne, Some(ExpectedLength::Exact(EXPECTED_LENGTH_WILDCARD_SHORT)));
    }

    #[test]
    fn test_external_authenticate_rejects_long_data() {
        let cmd_data = vec![0x00; EXPECTED_LENGTH_WILDCARD_SHORT];
        let err = HealthCardCommand::external_authenticate(&cmd_data).unwrap_err();

        match err {
            ExternalAuthenticateCommandError::CommandDataTooLong { length, max } => {
                assert_eq!(length, EXPECTED_LENGTH_WILDCARD_SHORT);
                assert_eq!(max, EXPECTED_LENGTH_WILDCARD_SHORT - 1);
            }
        }
    }
}
