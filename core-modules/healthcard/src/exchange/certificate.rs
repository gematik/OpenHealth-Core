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

use super::channel::CardChannelExt;
use super::error::ExchangeError;
use super::ids;

/// Defines which certificate file to read from the card.
#[derive(Clone, Copy, Debug)]
pub enum CertificateFile {
    /// X.509 certificate stored in `DF.ESIGN/EF.C.CH.AUT.E256`.
    ChAutE256,
    /// CV certificate stored in `MF/EF.C.eGK.AUT_CVC.E256`.
    EgkAutCvcE256,
}

fn select_certificate_file<S>(session: &mut S, certificate: CertificateFile) -> Result<(), ExchangeError>
where
    S: CardChannelExt,
{
    match certificate {
        CertificateFile::ChAutE256 => {
            session.execute_command_success(&HealthCardCommand::select_aid(&ids::df_esign_aid()))?;
            session.execute_command_success(&HealthCardCommand::select_fid_with_options(
                &ids::ef_cch_aut_e256_fid(),
                false,
                true,
                EXPECTED_LENGTH_WILDCARD_EXTENDED as i32,
            ))?;
        }
        CertificateFile::EgkAutCvcE256 => {
            session.execute_command_success(&HealthCardCommand::select(false, false))?;
            session.execute_command_success(&HealthCardCommand::select_fid_with_options(
                &ids::ef_c_egk_aut_cvc_e256_fid(),
                false,
                true,
                EXPECTED_LENGTH_WILDCARD_EXTENDED as i32,
            ))?;
        }
    }

    Ok(())
}

/// Retrieve the X.509 certificate stored in `DF.ESIGN/EF.C.CH.AUT.E256`.
///
/// The certificate is read in chunks using the READ BINARY command until the
/// card indicates the end of the file.
pub fn retrieve_certificate<S>(session: &mut S) -> Result<Vec<u8>, ExchangeError>
where
    S: CardChannelExt,
{
    retrieve_certificate_from(session, CertificateFile::ChAutE256)
}

/// Retrieve a certificate file from the card.
///
/// The certificate is read in chunks using the READ BINARY command until the
/// card indicates the end of the file.
pub fn retrieve_certificate_from<S>(session: &mut S, certificate: CertificateFile) -> Result<Vec<u8>, ExchangeError>
where
    S: CardChannelExt,
{
    select_certificate_file(session, certificate)?;

    let mut certificate = Vec::new();
    let mut offset: i32 = 0;

    loop {
        let read_command = HealthCardCommand::read_with_offset(offset)?;
        let response = session.execute_command(&read_command)?;
        let data = response.apdu.to_data();
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
    use crate::command::health_card_status::HealthCardResponseStatus;
    use crate::command::select_command::SelectCommand;
    use crate::exchange::test_utils::MockSession;

    #[test]
    fn certificate_read_until_eof() {
        let mut session = MockSession::with_extended_support(
            vec![vec![0x90, 0x00], vec![0x90, 0x00], vec![0xDE, 0xAD, 0x90, 0x00], vec![0xBE, 0xEF, 0x62, 0x82]],
            true,
        );
        let cert = retrieve_certificate(&mut session).unwrap();
        assert_eq!(cert, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn certificate_status_error() {
        let mut session = MockSession::with_extended_support(vec![vec![0x90, 0x00], vec![0x6A, 0x82]], true);

        let err = retrieve_certificate(&mut session).unwrap_err();
        match err {
            ExchangeError::UnexpectedStatus { status } | ExchangeError::Status(status) => {
                assert_eq!(status, HealthCardResponseStatus::FileNotFound)
            }
            other => panic!("unexpected error {other:?}"),
        }
    }

    #[test]
    fn cv_certificate_selects_master_file() {
        let mut session = MockSession::with_extended_support(
            vec![vec![0x90, 0x00], vec![0x90, 0x00], vec![0xDE, 0xAD, 0x90, 0x00], vec![0xBE, 0xEF, 0x62, 0x82]],
            true,
        );

        let cert = retrieve_certificate_from(&mut session, CertificateFile::EgkAutCvcE256).unwrap();
        assert_eq!(cert, vec![0xDE, 0xAD, 0xBE, 0xEF]);
        assert_eq!(
            session.recorded[0],
            HealthCardCommand::select(false, false).command_apdu(false).unwrap().to_bytes()
        );
        assert_eq!(
            session.recorded[1],
            HealthCardCommand::select_fid_with_options(
                &ids::ef_c_egk_aut_cvc_e256_fid(),
                false,
                true,
                EXPECTED_LENGTH_WILDCARD_EXTENDED as i32,
            )
            .command_apdu(false)
            .unwrap()
            .to_bytes()
        );
    }
}
