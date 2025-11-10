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

use crate::card::encrypted_pin_format2::EncryptedPinFormat2;
use crate::command::change_reference_data_command::ChangeReferenceDataCommand;
use crate::command::get_pin_status_command::GetPinStatusCommand;
use crate::command::health_card_command::HealthCardCommand;
use crate::command::health_card_command::HealthCardResponse;
use crate::command::health_card_status::HealthCardResponseStatus;
use crate::command::reset_retry_counter_command::ResetRetryCounterCommand;
use crate::command::reset_retry_counter_with_new_secret_command::ResetRetryCounterWithNewSecretCommand;
use crate::command::select_command::SelectCommand;
use crate::command::verify_pin_command::VerifyCommand;

use super::error::ExchangeError;
use super::ids;
use super::session::CardSessionExt;

/// Result of a PIN verification attempt.
#[derive(Debug, Clone)]
pub enum HealthCardVerifyPinResult {
    /// PIN verified successfully.
    Success(HealthCardResponse),
    /// PIN was wrong; retries remaining.
    WrongSecretWarning { response: HealthCardResponse, retries_left: u8 },
    /// The card is blocked for the requested PIN reference.
    CardBlocked(HealthCardResponse),
}

/// Methods for unblocking the PIN using the PUK/change reference data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockMethod {
    ChangeReferenceData,
    ResetRetryCounter,
    ResetRetryCounterWithNewSecret,
}

/// Verify the home PIN (`MRPIN.H`).
pub fn verify_pin<S>(session: &mut S, pin: &str) -> Result<HealthCardVerifyPinResult, ExchangeError>
where
    S: CardSessionExt,
{
    session.execute_command_success(&HealthCardCommand::select(false, false))?;
    let password_reference = ids::mr_pin_home_reference();

    let status_response = session.execute_command(&HealthCardCommand::get_pin_status(&password_reference, false))?;
    if status_response.status.is_success() {
        return Ok(HealthCardVerifyPinResult::Success(status_response));
    }

    let encrypted_pin = EncryptedPinFormat2::new(pin)?;
    let response =
        session.execute_command(&HealthCardCommand::verify_pin(&password_reference, false, &encrypted_pin))?;
    map_verify_response(response)
}

fn map_verify_response(response: HealthCardResponse) -> Result<HealthCardVerifyPinResult, ExchangeError> {
    match response.status {
        HealthCardResponseStatus::Success => Ok(HealthCardVerifyPinResult::Success(response)),
        HealthCardResponseStatus::PasswordBlocked => Ok(HealthCardVerifyPinResult::CardBlocked(response)),
        status => {
            if let Some(retries_left) = wrong_secret_retries(status) {
                Ok(HealthCardVerifyPinResult::WrongSecretWarning { response, retries_left })
            } else {
                Err(ExchangeError::unexpected(status))
            }
        }
    }
}

fn wrong_secret_retries(status: HealthCardResponseStatus) -> Option<u8> {
    use HealthCardResponseStatus::*;
    match status {
        WrongSecretWarningCount00 => Some(0),
        WrongSecretWarningCount01 => Some(1),
        WrongSecretWarningCount02 => Some(2),
        WrongSecretWarningCount03 => Some(3),
        WrongSecretWarningCount04 => Some(4),
        WrongSecretWarningCount05 => Some(5),
        WrongSecretWarningCount06 => Some(6),
        WrongSecretWarningCount07 => Some(7),
        WrongSecretWarningCount08 => Some(8),
        WrongSecretWarningCount09 => Some(9),
        WrongSecretWarningCount10 => Some(10),
        WrongSecretWarningCount11 => Some(11),
        WrongSecretWarningCount12 => Some(12),
        WrongSecretWarningCount13 => Some(13),
        WrongSecretWarningCount14 => Some(14),
        WrongSecretWarningCount15 => Some(15),
        _ => None,
    }
}

/// Unlock the home PIN using the specified method.
pub fn unlock_egk<S>(
    session: &mut S,
    method: UnlockMethod,
    puk: Option<&str>,
    old_secret: &str,
    new_secret: Option<&str>,
) -> Result<HealthCardResponseStatus, ExchangeError>
where
    S: CardSessionExt,
{
    session.execute_command_success(&HealthCardCommand::select(false, false))?;
    let password_reference = ids::mr_pin_home_reference();

    let response = match method {
        UnlockMethod::ChangeReferenceData => {
            let new_secret = new_secret.ok_or(ExchangeError::InvalidArgument("new secret required"))?;
            let old_pin = EncryptedPinFormat2::new(old_secret)?;
            let new_pin = EncryptedPinFormat2::new(new_secret)?;
            session.execute_command_success(&HealthCardCommand::change_reference_data(
                &password_reference,
                false,
                &old_pin,
                &new_pin,
            ))?
        }
        UnlockMethod::ResetRetryCounter => {
            let puk = puk.ok_or(ExchangeError::InvalidArgument("PUK must be provided"))?;
            let puk_enc = EncryptedPinFormat2::new(puk)?;
            session.execute_command_success(&HealthCardCommand::reset_retry_counter(
                &password_reference,
                false,
                &puk_enc,
            ))?
        }
        UnlockMethod::ResetRetryCounterWithNewSecret => {
            let puk = puk.ok_or(ExchangeError::InvalidArgument("PUK must be provided"))?;
            let new_secret = new_secret.ok_or(ExchangeError::InvalidArgument("new secret required"))?;
            let puk_enc = EncryptedPinFormat2::new(puk)?;
            let new_pin = EncryptedPinFormat2::new(new_secret)?;
            session.execute_command_success(&HealthCardCommand::reset_retry_counter_with_new_secret(
                &password_reference,
                false,
                &puk_enc,
                &new_pin,
            ))?
        }
    };

    Ok(response.status)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::apdu::CardResponseApdu;
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
            false
        }

        fn transmit(
            &mut self,
            _command: &crate::command::apdu::CardCommandApdu,
        ) -> Result<CardResponseApdu, Self::Error> {
            Ok(self.responses.remove(0))
        }
    }

    #[test]
    fn verify_pin_success_path() {
        let responses = vec![
            vec![0x90, 0x00], // select
            vec![0x90, 0x00], // get pin status success
        ];
        let mut session = MockSession::new(responses);
        match verify_pin(&mut session, "123456").unwrap() {
            HealthCardVerifyPinResult::Success(response) => {
                assert_eq!(response.status, HealthCardResponseStatus::Success)
            }
            other => panic!("unexpected result {other:?}"),
        }
    }

    #[test]
    fn verify_pin_wrong_secret() {
        let responses = vec![
            vec![0x90, 0x00], // select
            vec![0x63, 0xC1], // pin status indicates not performed
            vec![0x63, 0xC2], // verify returns warning count 02
        ];
        let mut session = MockSession::new(responses);
        match verify_pin(&mut session, "123456").unwrap() {
            HealthCardVerifyPinResult::WrongSecretWarning { retries_left, .. } => {
                assert_eq!(retries_left, 2);
            }
            other => panic!("unexpected result {other:?}"),
        }
    }

    #[test]
    fn unlock_change_reference_data_requires_new_pin() {
        let responses = vec![vec![0x90, 0x00], vec![0x90, 0x00]];
        let mut session = MockSession::new(responses);
        let err = unlock_egk(&mut session, UnlockMethod::ChangeReferenceData, None, "123456", Some("987654")).unwrap();
        assert_eq!(err, HealthCardResponseStatus::Success);
    }

    #[test]
    fn unlock_reset_retry_counter_requires_puk() {
        let responses = vec![vec![0x90, 0x00], vec![0x90, 0x00]];
        let mut session = MockSession::new(responses);
        let status =
            unlock_egk(&mut session, UnlockMethod::ResetRetryCounter, Some("123456"), "ignored", None).unwrap();
        assert_eq!(status, HealthCardResponseStatus::Success);
    }
}
