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

use crate::command::health_card_command::{ExpectedLength, HealthCardCommand};
use crate::command::health_card_status::GET_RANDOM_VALUES_STATUS;

/// CLA byte for the GET RANDOM VALUES command
const CLA: u8 = 0x80;

/// INS byte for the GET RANDOM VALUES command
const INS: u8 = 0x84;

/// P1 parameter with no meaning
const NO_MEANING: u8 = 0x00;

/// Extension trait for HealthCardCommand to provide GET RANDOM VALUES commands
pub trait GetRandomValuesCommand {
    /// Creates a HealthCardCommand to request random values from the card.
    /// Use case gemSpec_COS_3.14.0#14.9.5.1
    ///
    /// # Arguments
    /// * `length` - The number of random bytes to request.
    ///
    /// # Returns
    /// A HealthCardCommand for requesting random values.
    ///
    /// # REQ: GS-A_4367, GS-A_4368
    /// # | gemSpec_Krypt
    /// # | Random numbers are generated using the RNG of the health card.
    /// # This generator fulfills BSI-TR-03116#3.4 PTG.2 required by gemSpec_COS_3.14.0#14.9.5.1
    fn get_random_values(length: usize) -> HealthCardCommand;
}

impl GetRandomValuesCommand for HealthCardCommand {
    fn get_random_values(length: usize) -> HealthCardCommand {
        HealthCardCommand::new(
            GET_RANDOM_VALUES_STATUS.clone(),
            CLA,
            INS,
            NO_MEANING,
            NO_MEANING,
            None,
            Some(ExpectedLength::Exact(length)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_random_values_command() {
        // Test with different lengths
        let cmd = HealthCardCommand::get_random_values(8);
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, NO_MEANING);
        assert_eq!(cmd.p2, NO_MEANING);
        assert_eq!(cmd.data, None);
        assert_eq!(cmd.ne, Some(ExpectedLength::Exact(8)));

        let cmd = HealthCardCommand::get_random_values(16);
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, NO_MEANING);
        assert_eq!(cmd.p2, NO_MEANING);
        assert_eq!(cmd.data, None);
        assert_eq!(cmd.ne, Some(ExpectedLength::Exact(16)));
    }
}
