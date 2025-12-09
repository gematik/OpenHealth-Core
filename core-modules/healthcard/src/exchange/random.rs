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

use crate::command::get_random_command::GetRandomValuesCommand;
use crate::command::health_card_command::HealthCardCommand;
use crate::command::health_card_status::HealthCardResponseStatus;
use crate::command::select_command::SelectCommand;

use super::channel::CardChannelExt;
use super::error::ExchangeError;

/// Request cryptographically strong random bytes from the card RNG.
///
/// This follows gemSpec_COS_3.14.0#14.9.5.1 and first selects the master file
/// to ensure a clean context before invoking `GET RANDOM VALUES`.
pub fn get_random<S>(session: &mut S, length: usize) -> Result<Vec<u8>, ExchangeError>
where
    S: CardChannelExt,
{
    session.execute_command_success(&HealthCardCommand::select(false, false))?;

    let response = session.execute_command(&HealthCardCommand::get_random_values(length))?;
    match response.status {
        HealthCardResponseStatus::Success | HealthCardResponseStatus::SecurityStatusNotSatisfied => {
            Ok(response.apdu.to_data())
        }
        status => Err(ExchangeError::status(status)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::select_command::SelectCommand;
    use crate::exchange::test_utils::MockSession;

    #[test]
    fn random_success() {
        let mut session = MockSession::new(vec![vec![0x90, 0x00], vec![0xDE, 0xAD, 0x90, 0x00]]);
        let values = get_random(&mut session, 2).unwrap();
        assert_eq!(values, vec![0xDE, 0xAD]);
        assert_eq!(session.recorded.len(), 2);
        assert_eq!(
            session.recorded[0],
            HealthCardCommand::select(false, false).command_apdu(false).unwrap().to_bytes()
        );
    }
}
