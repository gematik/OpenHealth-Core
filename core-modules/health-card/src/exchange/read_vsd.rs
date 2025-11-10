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

use crate::command::health_card_command::HealthCardCommand;
use crate::command::health_card_status::HealthCardResponseStatus;
use crate::command::read_command::ReadCommand;
use crate::command::select_command::SelectCommand;

use super::error::ExchangeError;
use super::ids;
use super::session::CardSessionExt;

/// Read the insurance data (`EF.VD`) from the health card.
///
/// The function follows the steps outlined in gemSpec_ObjSys section 5.4 and
/// iteratively reads the file content until an end-of-file status is returned.
pub fn read_vsd<S>(session: &mut S) -> Result<Vec<u8>, ExchangeError>
where
    S: CardSessionExt,
{
    session.execute_command_success(&HealthCardCommand::select(false, false))?;
    session.execute_command_success(&HealthCardCommand::select_aid(&ids::df_hca_aid()))?;
    session.execute_command_success(&HealthCardCommand::select_fid(&ids::ef_vd_fid(), false))?;

    let mut buffer = Vec::new();
    let mut offset = 0;

    loop {
        let read_command = HealthCardCommand::read_with_offset(offset)?;
        let response = session.execute_command(&read_command)?;
        let chunk = response.apdu.data();
        if !chunk.is_empty() {
            offset = offset.saturating_add(chunk.len() as i32);
            buffer.extend_from_slice(&chunk);
        }

        match response.status {
            HealthCardResponseStatus::Success => continue,
            HealthCardResponseStatus::EndOfFileWarning | HealthCardResponseStatus::OffsetTooBig => break,
            status => return Err(ExchangeError::status(status)),
        }
    }

    Ok(buffer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::apdu::CardResponseApdu;
    use crate::exchange::session::CardSession;

    struct MockSession {
        responses: Vec<CardResponseApdu>,
        recorded: Vec<Vec<u8>>,
    }

    impl MockSession {
        fn new(responses: Vec<Vec<u8>>) -> Self {
            let responses = responses.into_iter().map(|raw| CardResponseApdu::new(&raw).unwrap()).collect();
            Self { responses, recorded: Vec::new() }
        }
    }

    impl CardSession for MockSession {
        type Error = std::convert::Infallible;

        fn supports_extended_length(&self) -> bool {
            false
        }

        fn transmit(
            &mut self,
            command: &crate::command::apdu::CardCommandApdu,
        ) -> Result<CardResponseApdu, Self::Error> {
            self.recorded.push(command.apdu());
            Ok(self.responses.remove(0))
        }
    }

    #[test]
    fn read_vsd_collects_data_until_eof() {
        // select MF, DF.HCA, EF.VD -> all return 9000, then read returns two chunks and EOF warning
        let responses = vec![
            vec![0x90, 0x00],
            vec![0x90, 0x00],
            vec![0x90, 0x00],
            vec![0x01, 0x02, 0x90, 0x00],
            vec![0x03, 0x90, 0x00],
            vec![0x62, 0x82], // End of file warning
        ];
        let mut session = MockSession::new(responses);
        let data = read_vsd(&mut session).unwrap();
        assert_eq!(data, vec![0x01, 0x02, 0x03]);
        assert_eq!(session.recorded.len(), 6);
    }

    #[test]
    fn read_vsd_propagates_status() {
        let responses = vec![vec![0x90, 0x00], vec![0x90, 0x00], vec![0x90, 0x00], vec![0x6A, 0x82]];
        let mut session = MockSession::new(responses);
        let err = read_vsd(&mut session).unwrap_err();
        match err {
            ExchangeError::Status(status) => assert_eq!(status, HealthCardResponseStatus::FileNotFound),
            other => panic!("unexpected error {other:?}"),
        }
    }
}
