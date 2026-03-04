// SPDX-FileCopyrightText: Copyright 2026 gematik GmbH
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
use crate::command::health_card_status::INTERNAL_AUTHENTICATE_STATUS;
use asn1::maybe_zeroizing_vec::VecOfU8;

/// CLA byte for INTERNAL AUTHENTICATE (ISO/IEC 7816-4).
const CLA: u8 = 0x00;
/// INS byte for INTERNAL AUTHENTICATE (ISO/IEC 7816-4).
const INS: u8 = 0x88;
/// P1 parameter: algorithm info already present on card.
const P1: u8 = 0x00;
/// P2 parameter: key reference already present on card.
const P2: u8 = 0x00;

/// Extension trait for HealthCardCommand to provide INTERNAL AUTHENTICATE command.
pub trait InternalAuthenticateCommand {
    /// Creates a HealthCardCommand for INTERNAL AUTHENTICATE (gemSpec_COS_3.14.0, 14.7.4).
    ///
    /// The command is a case 4 APDU (data present, response expected). The expected response
    /// length is specified as wildcard (short/extended) to allow the full response to fit.
    ///
    /// Use case: contactless authentication with token data.
    fn internal_authenticate(challenge: &[u8]) -> HealthCardCommand;
}

impl InternalAuthenticateCommand for HealthCardCommand {
    fn internal_authenticate(challenge: &[u8]) -> HealthCardCommand {
        HealthCardCommand::new(
            INTERNAL_AUTHENTICATE_STATUS.clone(),
            CLA,
            INS,
            P1,
            P2,
            Some(VecOfU8::new_nonzeroizing(challenge.to_vec())),
            Some(ExpectedLength::Any),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_internal_authenticate_command() {
        let challenge = vec![0x01, 0x02, 0x03, 0x04];
        let cmd = HealthCardCommand::internal_authenticate(&challenge);

        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, P1);
        assert_eq!(cmd.p2, P2);
        assert_eq!(cmd.data, Some(VecOfU8::new_nonzeroizing(challenge)));
        assert_eq!(cmd.ne, Some(ExpectedLength::Any));
    }
}
