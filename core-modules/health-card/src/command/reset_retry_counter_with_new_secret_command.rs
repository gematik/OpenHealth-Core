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
use crate::command::health_card_status::UNLOCK_EGK_STATUS;

/// CLA byte for the UNLOCK eGK command
const CLA: u8 = 0x00;

/// INS byte for the UNLOCK eGK command
const UNLOCK_EGK_INS: u8 = 0x2C;

/// Mode for verification data with new secret
const MODE_VERIFICATION_DATA_NEW_SECRET: u8 = 0x00;

/// Extension trait for HealthCardCommand to provide RESET RETRY COUNTER WITH NEW SECRET commands
pub trait ResetRetryCounterWithNewSecretCommand {
    /// Creates a HealthCardCommand for the RESET RETRY COUNTER WITH NEW SECRET command.
    /// (gemSpec_COS_3.14.0#14.6.5.2)
    ///
    /// This command is used to reset the retry counter of a password and set a new password.
    ///
    /// # Arguments
    /// * `password_reference` - The password reference for the unlock operation.
    /// * `df_specific` - Indicates if the operation is DF-specific.
    /// * `puk` - The PUK (Personal Unblocking Key) in encrypted format.
    /// * `new_secret` - The new secret (PIN) in encrypted format.
    ///
    /// # Returns
    /// A `HealthCardCommand` for the RESET RETRY COUNTER WITH NEW SECRET operation.
    fn reset_retry_counter_with_new_secret(
        password_reference: &PasswordReference,
        df_specific: bool,
        puk: &EncryptedPinFormat2,
        new_secret: &EncryptedPinFormat2,
    ) -> HealthCardCommand;
}

impl ResetRetryCounterWithNewSecretCommand for HealthCardCommand {
    fn reset_retry_counter_with_new_secret(
        password_reference: &PasswordReference,
        df_specific: bool,
        puk: &EncryptedPinFormat2,
        new_secret: &EncryptedPinFormat2,
    ) -> HealthCardCommand {
        // Combine the bytes from PUK and new secret
        let mut combined_data = Vec::new();
        combined_data.extend_from_slice(&puk.bytes);
        combined_data.extend_from_slice(&new_secret.bytes);

        HealthCardCommand {
            expected_status: UNLOCK_EGK_STATUS.clone(),
            cla: CLA,
            ins: UNLOCK_EGK_INS,
            p1: MODE_VERIFICATION_DATA_NEW_SECRET,
            p2: password_reference.calculate_key_reference(df_specific),
            data: Some(combined_data),
            ne: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reset_retry_counter_with_new_secret() {
        // Create test objects
        let password_ref = PasswordReference::new(5);
        let puk_data = vec![0x25, 0x12, 0x34, 0x56, 0xFF, 0xFF, 0xFF, 0xFF];
        let new_pin_data = vec![0x25, 0x65, 0x43, 0x21, 0xFF, 0xFF, 0xFF, 0xFF];
        let puk = EncryptedPinFormat2 { bytes: puk_data.clone() };
        let new_secret = EncryptedPinFormat2 { bytes: new_pin_data.clone() };

        // Test with df_specific = false
        let cmd = HealthCardCommand::reset_retry_counter_with_new_secret(
            &password_ref,
            false,
            &puk,
            &new_secret
        );

        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, UNLOCK_EGK_INS);
        assert_eq!(cmd.p1, MODE_VERIFICATION_DATA_NEW_SECRET);
        assert_eq!(cmd.p2, password_ref.calculate_key_reference(false));

        let mut expected_data = Vec::new();
        expected_data.extend_from_slice(&puk_data);
        expected_data.extend_from_slice(&new_pin_data);

        assert_eq!(cmd.data, Some(expected_data.clone()));
        assert_eq!(cmd.ne, None);

        // Test with df_specific = true
        let cmd = HealthCardCommand::reset_retry_counter_with_new_secret(
            &password_ref,
            true,
            &puk,
            &new_secret
        );

        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, UNLOCK_EGK_INS);
        assert_eq!(cmd.p1, MODE_VERIFICATION_DATA_NEW_SECRET);
        assert_eq!(cmd.p2, password_ref.calculate_key_reference(true));
        assert_eq!(cmd.data, Some(expected_data));
        assert_eq!(cmd.ne, None);
    }
}