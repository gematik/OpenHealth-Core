// SPDX-FileCopyrightText: Copyright 2025 - 2026 gematik GmbH
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

use crate::card::encrypted_pin_format2::{EncryptedPinFormat2, PinBlockError};
use crate::command::change_reference_data_command::ChangeReferenceDataCommand;
use crate::command::get_pin_status_command::GetPinStatusCommand;
use crate::command::health_card_command::HealthCardCommand;
use crate::command::health_card_command::HealthCardResponse;
use crate::command::health_card_status::HealthCardResponseStatus;
use crate::command::reset_retry_counter_command::ResetRetryCounterCommand;
use crate::command::reset_retry_counter_with_new_secret_command::ResetRetryCounterWithNewSecretCommand;
use crate::command::select_command::SelectCommand;
use crate::command::verify_pin_command::VerifyCommand;

use super::channel::CardChannelExt;
use super::error::ExchangeError;
use super::ids;
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

const MIN_PIN_LEN: usize = 4;
const MAX_PIN_LEN: usize = 12;

/// Plain-text PIN value that is zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CardPin {
    digits: Vec<u8>,
}

impl CardPin {
    pub fn new(pin: &str) -> Result<Self, PinBlockError> {
        if pin.len() < MIN_PIN_LEN {
            return Err(PinBlockError::TooShort { length: pin.len(), min: MIN_PIN_LEN });
        }
        if pin.len() > MAX_PIN_LEN {
            return Err(PinBlockError::TooLong { length: pin.len(), max: MAX_PIN_LEN });
        }
        let mut digits = Vec::with_capacity(pin.len());
        for c in pin.chars() {
            if !c.is_ascii_digit() {
                return Err(PinBlockError::NonDigit(c));
            }
            digits.push(c as u8);
        }
        Ok(Self { digits })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.digits
    }
}

impl fmt::Debug for CardPin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CardPin").field("len", &self.digits.len()).finish_non_exhaustive()
    }
}

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
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum UnlockMethod {
    ChangeReferenceData,
    ResetRetryCounter,
    ResetRetryCounterWithNewSecret,
}

/// Verify the home PIN (`MRPIN.H`).
pub fn verify_pin<S>(session: &mut S, pin: &CardPin) -> Result<HealthCardVerifyPinResult, ExchangeError>
where
    S: CardChannelExt,
{
    session.execute_command_success(&HealthCardCommand::select(false, false))?;
    let password_reference = ids::mr_pin_home_reference();

    let status_response = session.execute_command(&HealthCardCommand::get_pin_status(&password_reference, false))?;
    if status_response.status.is_success() {
        return Ok(HealthCardVerifyPinResult::Success(status_response));
    }

    let encrypted_pin = EncryptedPinFormat2::new_from_digits(pin.as_bytes())?;
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
        WrongSecretWarningCount01 => Some(1),
        WrongSecretWarningCount02 => Some(2),
        WrongSecretWarningCount03 => Some(3),
        _ => None,
    }
}

/// Unlock the home PIN using the specified method.
pub fn unlock_egk<S>(
    session: &mut S,
    method: UnlockMethod,
    puk: Option<&CardPin>,
    old_secret: &CardPin,
    new_secret: Option<&CardPin>,
) -> Result<HealthCardResponseStatus, ExchangeError>
where
    S: CardChannelExt,
{
    session.execute_command_success(&HealthCardCommand::select(false, false))?;
    let password_reference = ids::mr_pin_home_reference();

    let response = match method {
        UnlockMethod::ChangeReferenceData => {
            let new_secret = new_secret.ok_or_else(|| ExchangeError::invalid_argument("new secret required"))?;
            let old_pin = EncryptedPinFormat2::new_from_digits(old_secret.as_bytes())?;
            let new_pin = EncryptedPinFormat2::new_from_digits(new_secret.as_bytes())?;
            session.execute_command_success(&HealthCardCommand::change_reference_data(
                &password_reference,
                false,
                &old_pin,
                &new_pin,
            ))?
        }
        UnlockMethod::ResetRetryCounter => {
            let puk = puk.ok_or_else(|| ExchangeError::invalid_argument("PUK must be provided"))?;
            let puk_enc = EncryptedPinFormat2::new_from_digits(puk.as_bytes())?;
            session.execute_command_success(&HealthCardCommand::reset_retry_counter(
                &password_reference,
                false,
                &puk_enc,
            ))?
        }
        UnlockMethod::ResetRetryCounterWithNewSecret => {
            let puk = puk.ok_or_else(|| ExchangeError::invalid_argument("PUK must be provided"))?;
            let new_secret = new_secret.ok_or_else(|| ExchangeError::invalid_argument("new secret required"))?;
            let puk_enc = EncryptedPinFormat2::new_from_digits(puk.as_bytes())?;
            let new_pin = EncryptedPinFormat2::new_from_digits(new_secret.as_bytes())?;
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
    use crate::exchange::test_utils::MockSession;

    #[test]
    fn verify_pin_success_path() {
        let responses = vec![
            vec![0x90, 0x00], // select
            vec![0x90, 0x00], // get pin status success
        ];
        let mut session = MockSession::new(responses);
        let pin = CardPin::new("123456").unwrap();
        match verify_pin(&mut session, &pin).unwrap() {
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
        let pin = CardPin::new("123456").unwrap();
        match verify_pin(&mut session, &pin).unwrap() {
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
        let old_pin = CardPin::new("123456").unwrap();
        let new_pin = CardPin::new("987654").unwrap();
        let err = unlock_egk(&mut session, UnlockMethod::ChangeReferenceData, None, &old_pin, Some(&new_pin)).unwrap();
        assert_eq!(err, HealthCardResponseStatus::Success);
    }

    #[test]
    fn unlock_reset_retry_counter_requires_puk() {
        let responses = vec![vec![0x90, 0x00], vec![0x90, 0x00]];
        let mut session = MockSession::new(responses);
        let puk = CardPin::new("123456").unwrap();
        let placeholder = CardPin::new("0000").unwrap();
        let status = unlock_egk(&mut session, UnlockMethod::ResetRetryCounter, Some(&puk), &placeholder, None).unwrap();
        assert_eq!(status, HealthCardResponseStatus::Success);
    }
}
