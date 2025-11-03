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

use crate::command::apdu::EXPECTED_LENGTH_WILDCARD_EXTENDED;
use crate::command::health_card_command::HealthCardCommand;
use crate::command::health_card_status::HealthCardResponseStatus;
use crate::command::read_command::ReadCommand;
use crate::command::select_command::SelectCommand;

use super::error::ExchangeError;
use super::ids;
use super::session::CardSessionExt;

/// Retrieve the X.509 certificate stored in `DF.ESIGN/EF.C.CH.AUT.E256`.
///
/// The certificate is read in chunks using the READ BINARY command until the
/// card indicates the end of the file.
pub fn retrieve_certificate<S>(session: &mut S) -> Result<Vec<u8>, ExchangeError>
where
    S: CardSessionExt,
{
    session.execute_command_success(&HealthCardCommand::select_aid(&ids::df_esign_aid()))?;
    session.execute_command_success(&HealthCardCommand::select_fid_with_options(
        &ids::ef_cch_aut_e256_fid(),
        false,
        true,
        EXPECTED_LENGTH_WILDCARD_EXTENDED as i32,
    ))?;

    let mut certificate = Vec::new();
    let mut offset = 0;

    loop {
        let response = session.execute_command(&HealthCardCommand::read_with_offset(offset))?;
        let data = response.apdu.data();
        if !data.is_empty() {
            offset = offset.saturating_add(data.len() as i32);
            certificate.extend_from_slice(&data);
        }

        match response.status {
            HealthCardResponseStatus::Success => continue,
            HealthCardResponseStatus::EndOfFileWarning | HealthCardResponseStatus::OffsetTooBig => break,
            status => return Err(ExchangeError::status(status)),
        }
    }

    Ok(certificate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::apdu::CardResponseApdu;
    use crate::command::health_card_status::HealthCardResponseStatus;
    use crate::exchange::session::CardSession;

    struct MockSession {
        responses: Vec<CardResponseApdu>,
    }

    impl MockSession {
        fn new(responses: Vec<Vec<u8>>) -> Self {
            let responses = responses.into_iter().map(|raw| CardResponseApdu::new(&raw).unwrap()).collect();
            Self { responses }
        }
    }

    impl CardSession for MockSession {
        type Error = std::convert::Infallible;

        fn supports_extended_length(&self) -> bool {
            true
        }

        fn transmit(
            &mut self,
            _command: &crate::command::apdu::CardCommandApdu,
        ) -> Result<CardResponseApdu, Self::Error> {
            Ok(self.responses.remove(0))
        }
    }

    #[test]
    fn certificate_read_until_eof() {
        let mut session = MockSession::new(vec![
            vec![0x90, 0x00],
            vec![0x90, 0x00],
            vec![0xDE, 0xAD, 0x90, 0x00],
            vec![0xBE, 0xEF, 0x62, 0x82],
        ]);
        let cert = retrieve_certificate(&mut session).unwrap();
        assert_eq!(cert, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn certificate_status_error() {
        let mut session = MockSession::new(vec![vec![0x90, 0x00], vec![0x6A, 0x82]]);

        let err = retrieve_certificate(&mut session).unwrap_err();
        match err {
            ExchangeError::UnexpectedStatus { status } | ExchangeError::Status(status) => {
                assert_eq!(status, HealthCardResponseStatus::FileNotFound)
            }
            other => panic!("unexpected error {other:?}"),
        }
    }
}
