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

use crate::card::card_key_reference::CardKeyReference;
use crate::card::encrypted_pin_format2::EncryptedPinFormat2;
use crate::card::password_reference::PasswordReference;
use crate::command::health_card_command::HealthCardCommand;
use crate::command::health_card_status::VERIFY_SECRET_STATUS;

/// CLA byte for the VERIFY SECRET command
const CLA: u8 = 0x00;

/// INS byte for the VERIFY SECRET command
const VERIFY_SECRET_INS: u8 = 0x20;

/// Mode for verification data
const MODE_VERIFICATION_DATA: u8 = 0x00;

/// Extension trait for HealthCardCommand to provide VERIFY SECRET commands
pub trait VerifyCommand {
    /// Creates a HealthCardCommand for the VERIFY SECRET command.
    /// (gemSpec_COS_3.14.0#14.6.6.1)
    ///
    /// # Arguments
    /// * `password_reference` - The password reference for the verification.
    /// * `df_specific` - Indicates if the verification is DF-specific.
    /// * `pin` - The PIN (Personal Identification Number) in encrypted format.
    fn verify_pin(
        password_reference: &PasswordReference,
        df_specific: bool,
        pin: &EncryptedPinFormat2,
    ) -> HealthCardCommand;
}

impl VerifyCommand for HealthCardCommand {
    fn verify_pin(
        password_reference: &PasswordReference,
        df_specific: bool,
        pin: &EncryptedPinFormat2,
    ) -> HealthCardCommand {
        HealthCardCommand {
            expected_status: VERIFY_SECRET_STATUS.clone(),
            cla: CLA,
            ins: VERIFY_SECRET_INS,
            p1: MODE_VERIFICATION_DATA,
            p2: password_reference.calculate_key_reference(df_specific),
            data: Some(pin.bytes.clone()),
            ne: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::card::encrypted_pin_format2::EncryptedPinFormat2;
    use crate::card::password_reference::PasswordReference;

    #[test]
    fn test_verify_pin_command() {
        // Create test objects
        let password_ref = PasswordReference::new(3);
        let pin_data = vec![0x25, 0x12, 0x34, 0x56, 0xFF, 0xFF, 0xFF, 0xFF];
        let encrypted_pin = EncryptedPinFormat2 { bytes: pin_data.clone() };

        // Test with df_specific = true
        let cmd = HealthCardCommand::verify_pin(&password_ref, true, &encrypted_pin);
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, VERIFY_SECRET_INS);
        assert_eq!(cmd.p1, MODE_VERIFICATION_DATA);
        assert_eq!(cmd.p2, password_ref.calculate_key_reference(true));
        assert_eq!(cmd.data, Some(pin_data.clone()));
        assert_eq!(cmd.ne, None);

        // Test with df_specific = false
        let cmd = HealthCardCommand::verify_pin(&password_ref, false, &encrypted_pin);
        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, VERIFY_SECRET_INS);
        assert_eq!(cmd.p1, MODE_VERIFICATION_DATA);
        assert_eq!(cmd.p2, password_ref.calculate_key_reference(false));
        assert_eq!(cmd.data, Some(pin_data));
        assert_eq!(cmd.ne, None);
    }
}
