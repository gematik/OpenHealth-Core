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
use crate::command::health_card_status::CHANGE_REFERENCE_DATA_STATUS;

/// CLA byte for the CHANGE REFERENCE DATA command
const CLA: u8 = 0x00;

/// INS byte for the CHANGE REFERENCE DATA command
const INS: u8 = 0x24;

/// Mode for verification data
const MODE_VERIFICATION_DATA: u8 = 0x00;

/// Extension trait for HealthCardCommand to provide CHANGE REFERENCE DATA commands
pub trait ChangeReferenceDataCommand {
    /// Creates a HealthCardCommand to change a secret.
    ///
    /// Use case change reference data gemSpec_COS_3.14.0#14.6.1.1
    ///
    /// # Arguments
    /// * `password_reference` - The `PasswordReference` to change.
    /// * `df_specific` - `true` if the reference is DF-specific, `false` otherwise.
    /// * `old_secret` - The current secret.
    /// * `new_secret` - The new secret.
    ///
    /// # Returns
    /// A `HealthCardCommand` for changing the reference data.
    fn change_reference_data(
        password_reference: &PasswordReference,
        df_specific: bool,
        old_secret: &EncryptedPinFormat2,
        new_secret: &EncryptedPinFormat2,
    ) -> HealthCardCommand;
}

impl ChangeReferenceDataCommand for HealthCardCommand {
    fn change_reference_data(
        password_reference: &PasswordReference,
        df_specific: bool,
        old_secret: &EncryptedPinFormat2,
        new_secret: &EncryptedPinFormat2,
    ) -> HealthCardCommand {
        // Combine the bytes from old and new secrets
        let mut combined_data = Vec::new();
        combined_data.extend_from_slice(old_secret.as_bytes());
        combined_data.extend_from_slice(new_secret.as_bytes());

        HealthCardCommand::new(
            CHANGE_REFERENCE_DATA_STATUS.clone(),
            CLA,
            INS,
            MODE_VERIFICATION_DATA,
            password_reference.calculate_key_reference(df_specific),
            Some(combined_data),
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_change_reference_data_command() {
        // Create test objects
        let password_reference = PasswordReference::new(10).unwrap();
        let old_pin_data = vec![0x25, 0x12, 0x34, 0x56, 0xFF, 0xFF, 0xFF, 0xFF];
        let new_pin_data = vec![0x25, 0x65, 0x43, 0x21, 0xFF, 0xFF, 0xFF, 0xFF];
        let old_secret = EncryptedPinFormat2::from_encrypted_bytes(old_pin_data.clone()).unwrap();
        let new_secret = EncryptedPinFormat2::from_encrypted_bytes(new_pin_data.clone()).unwrap();

        let command = HealthCardCommand::change_reference_data(&password_reference, false, &old_secret, &new_secret);

        assert_eq!(command.cla, CLA);
        assert_eq!(command.ins, INS);
        assert_eq!(command.p1, MODE_VERIFICATION_DATA);
        assert_eq!(command.p2, password_reference.calculate_key_reference(false));

        let mut expected_data = Vec::new();
        expected_data.extend_from_slice(&old_pin_data);
        expected_data.extend_from_slice(&new_pin_data);

        assert_eq!(command.data, Some(expected_data));
        assert_eq!(command.ne, None);

        let command = HealthCardCommand::change_reference_data(&password_reference, true, &old_secret, &new_secret);

        assert_eq!(command.p2, password_reference.calculate_key_reference(true));
    }
}
