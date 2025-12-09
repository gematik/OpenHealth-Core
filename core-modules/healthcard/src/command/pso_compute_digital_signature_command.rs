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
use crate::command::health_card_status::PSO_COMPUTE_DIGITAL_SIGNATURE_STATUS;

/// CLA byte for the PSO COMPUTE DIGITAL SIGNATURE command
const CLA: u8 = 0x00;

/// INS byte for the PSO COMPUTE DIGITAL SIGNATURE command
const INS: u8 = 0x2A;

/// P1 parameter for the PSO COMPUTE DIGITAL SIGNATURE command
const P1: u8 = 0x9E;

/// P2 parameter for the PSO COMPUTE DIGITAL SIGNATURE command
const P2: u8 = 0x9A;

/// Extension trait for HealthCardCommand to provide PSO COMPUTE DIGITAL SIGNATURE command
pub trait PsoComputeDigitalSignatureCommand {
    /// Creates a HealthCardCommand for the PSO COMPUTE DIGITAL SIGNATURE command.
    /// (gemSpec_COS_3.14.0#14.8.2)
    ///
    /// # Arguments
    /// * `data_to_be_signed` - The data to be signed.
    fn pso_compute_digital_signature(data_to_be_signed: &[u8]) -> HealthCardCommand;
}

impl PsoComputeDigitalSignatureCommand for HealthCardCommand {
    fn pso_compute_digital_signature(data_to_be_signed: &[u8]) -> HealthCardCommand {
        HealthCardCommand::new(
            PSO_COMPUTE_DIGITAL_SIGNATURE_STATUS.clone(),
            CLA,
            INS,
            P1,
            P2,
            Some(data_to_be_signed.to_vec()),
            Some(ExpectedLength::Any),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pso_compute_digital_signature() {
        // Test with simple data
        let data = [0x01, 0x02, 0x03, 0x04];
        let cmd = HealthCardCommand::pso_compute_digital_signature(&data);

        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, P1);
        assert_eq!(cmd.p2, P2);
        assert_eq!(cmd.data, Some(data.to_vec()));
        assert_eq!(cmd.ne, Some(ExpectedLength::Any));

        // Test with empty data
        let empty_data: [u8; 0] = [];
        let cmd = HealthCardCommand::pso_compute_digital_signature(&empty_data);

        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, P1);
        assert_eq!(cmd.p2, P2);
        assert_eq!(cmd.data, Some(vec![]));
        assert_eq!(cmd.ne, Some(ExpectedLength::Any));

        // Test with longer data
        let long_data = (0..100).map(|i| i as u8).collect::<Vec<u8>>();
        let cmd = HealthCardCommand::pso_compute_digital_signature(&long_data);

        assert_eq!(cmd.cla, CLA);
        assert_eq!(cmd.ins, INS);
        assert_eq!(cmd.p1, P1);
        assert_eq!(cmd.p2, P2);
        assert_eq!(cmd.data, Some(long_data.clone()));
        assert_eq!(cmd.ne, Some(ExpectedLength::Any));
    }
}
