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
use crate::command::health_card_status::LIST_PUBLIC_KEY_STATUS;

/// CLA byte for LIST PUBLIC KEY command (proprietary GET DATA variant).
const CLA: u8 = 0x80;

/// INS byte for LIST PUBLIC KEY command (proprietary GET DATA variant).
const INS: u8 = 0xCA;

/// P1 for listing public key identifiers.
const P1: u8 = 0x01;

/// P2 for listing public key identifiers.
const P2: u8 = 0x00;

/// Extension trait for HealthCardCommand to provide LIST PUBLIC KEY command.
pub trait ListPublicKeyCommand {
    /// Creates a HealthCardCommand for LIST PUBLIC KEY (gemSpec_COS_3.14.0#14.9.7).
    fn list_public_keys() -> HealthCardCommand;
}

impl ListPublicKeyCommand for HealthCardCommand {
    fn list_public_keys() -> HealthCardCommand {
        HealthCardCommand::new(LIST_PUBLIC_KEY_STATUS.clone(), CLA, INS, P1, P2, None, Some(ExpectedLength::Any))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_public_keys() {
        let cmd = HealthCardCommand::list_public_keys();
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, P1);
        assert_eq!(cmd.p2, P2);
        assert_eq!(cmd.data, None);
        assert_eq!(cmd.ne, Some(ExpectedLength::Any));
    }
}
