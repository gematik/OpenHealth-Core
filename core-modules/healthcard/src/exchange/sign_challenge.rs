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

use crate::card::pso_algorithm::PsoAlgorithm;
use crate::command::health_card_command::HealthCardCommand;
use crate::command::manage_security_environment_command::ManageSecurityEnvironmentCommand;
use crate::command::pso_compute_digital_signature_command::PsoComputeDigitalSignatureCommand;
use crate::command::select_command::SelectCommand;

use super::channel::CardChannelExt;
use super::error::ExchangeError;
use super::ids;

/// Sign a challenge using the card holder authentication key from `DF.ESIGN`.
///
/// This configuration uses ECDSA over the brainpool curve chosen by DF.ESIGN.
pub fn sign_challenge<S>(session: &mut S, challenge: &[u8]) -> Result<Vec<u8>, ExchangeError>
where
    S: CardChannelExt,
{
    session.execute_command_success(&HealthCardCommand::select_aid(&ids::df_esign_aid()))?;
    session.execute_command_success(&HealthCardCommand::manage_sec_env_for_signing(
        PsoAlgorithm::SignVerifyEcdsa,
        &ids::prk_ch_aut_e256(),
        true,
    )?)?;

    let response = session.execute_command_success(&HealthCardCommand::pso_compute_digital_signature(challenge))?;
    Ok(response.apdu.to_data())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exchange::test_utils::MockSession;

    #[test]
    fn sign_challenge_success() {
        let mut session =
            MockSession::new(vec![vec![0x90, 0x00], vec![0x90, 0x00], vec![0xDE, 0xAD, 0xBE, 0xEF, 0x90, 0x00]]);
        let signature = sign_challenge(&mut session, &[0x01, 0x02]).unwrap();
        assert_eq!(signature, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }
}
