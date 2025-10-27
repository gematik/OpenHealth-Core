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

use lazy_static::lazy_static;
use std::collections::HashMap;

/// All response status codes
/// gemSpec_COS_3.14.0#16.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HealthCardResponseStatus {
    Success,
    UnknownException,
    UnknownStatus,
    DataTruncated,
    CorruptDataWarning,
    EndOfFileWarning,
    EndOfRecordWarning,
    UnsuccessfulSearch,
    FileDeactivated,
    FileTerminated,
    RecordDeactivated,
    TransportStatusTransportPin,
    TransportStatusEmptyPin,
    PasswordDisabled,
    AuthenticationFailure,
    NoAuthentication,
    RetryCounterCount00,
    RetryCounterCount01,
    RetryCounterCount02,
    RetryCounterCount03,
    RetryCounterCount04,
    RetryCounterCount05,
    RetryCounterCount06,
    RetryCounterCount07,
    RetryCounterCount08,
    RetryCounterCount09,
    RetryCounterCount10,
    RetryCounterCount11,
    RetryCounterCount12,
    RetryCounterCount13,
    RetryCounterCount14,
    RetryCounterCount15,
    UpdateRetryWarningCount00,
    UpdateRetryWarningCount01,
    UpdateRetryWarningCount02,
    UpdateRetryWarningCount03,
    UpdateRetryWarningCount04,
    UpdateRetryWarningCount05,
    UpdateRetryWarningCount06,
    UpdateRetryWarningCount07,
    UpdateRetryWarningCount08,
    UpdateRetryWarningCount09,
    UpdateRetryWarningCount10,
    UpdateRetryWarningCount11,
    UpdateRetryWarningCount12,
    UpdateRetryWarningCount13,
    UpdateRetryWarningCount14,
    UpdateRetryWarningCount15,
    WrongSecretWarningCount00,
    WrongSecretWarningCount01,
    WrongSecretWarningCount02,
    WrongSecretWarningCount03,
    WrongSecretWarningCount04,
    WrongSecretWarningCount05,
    WrongSecretWarningCount06,
    WrongSecretWarningCount07,
    WrongSecretWarningCount08,
    WrongSecretWarningCount09,
    WrongSecretWarningCount10,
    WrongSecretWarningCount11,
    WrongSecretWarningCount12,
    WrongSecretWarningCount13,
    WrongSecretWarningCount14,
    WrongSecretWarningCount15,
    EncipherError,
    KeyInvalid,
    ObjectTerminated,
    ParameterMismatch,
    MemoryFailure,
    WrongRecordLength,
    ChannelClosed,
    NoMoreChannelsAvailable,
    VolatileKeyWithoutLcs,
    WrongFileType,
    SecurityStatusNotSatisfied,
    CommandBlocked,
    KeyExpired,
    PasswordBlocked,
    KeyAlreadyPresent,
    NoKeyReference,
    NoPrkReference,
    NoPukReference,
    NoRandom,
    NoRecordLifeCycleStatus,
    PasswordNotUsable,
    WrongRandomLength,
    WrongRandomOrNoKeyReference,
    WrongPasswordLength,
    NoCurrentEf,
    IncorrectSmDo,
    NewFileSizeWrong,
    NumberPreconditionWrong,
    NumberScenarioWrong,
    VerificationError,
    WrongCipherText,
    WrongToken,
    UnsupportedFunction,
    FileNotFound,
    RecordNotFound,
    DataTooBig,
    FullRecordList,
    MessageTooLong,
    OutOfMemory,
    InconsistentKeyReference,
    WrongKeyReference,
    KeyNotFound,
    KeyOrPrkNotFound,
    PasswordNotFound,
    PrkNotFound,
    PukNotFound,
    DuplicatedObjects,
    DfNameExists,
    OffsetTooBig,
    InstructionNotSupported,
    PukBlocked,
}

impl std::fmt::Display for HealthCardResponseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl HealthCardResponseStatus {
    /// Gets the status from a status word (SW) for a general authenticate command.
    pub fn from_general_authenticate_status(sw: u16) -> Self {
        GENERAL_AUTHENTICATE_STATUS.get(&sw).copied().unwrap_or(HealthCardResponseStatus::UnknownStatus)
    }

    /// Gets the status from a status word (SW) for a PIN-related command.
    pub fn from_pin_status(sw: u16) -> Self {
        PIN_STATUS.get(&sw).copied().unwrap_or(HealthCardResponseStatus::UnknownStatus)
    }

    /// Gets the status from a status word (SW) for a manage security environment command.
    pub fn from_manage_security_environment_status(sw: u16) -> Self {
        MANAGE_SECURITY_ENVIRONMENT_STATUS.get(&sw).copied().unwrap_or(HealthCardResponseStatus::UnknownStatus)
    }

    /// Gets the status from a status word (SW) for a PSO compute digital signature command.
    pub fn from_pso_compute_digital_signature_status(sw: u16) -> Self {
        PSO_COMPUTE_DIGITAL_SIGNATURE_STATUS.get(&sw).copied().unwrap_or(HealthCardResponseStatus::UnknownStatus)
    }

    /// Gets the status from a status word (SW) for a read command.
    pub fn from_read_status(sw: u16) -> Self {
        READ_STATUS.get(&sw).copied().unwrap_or(HealthCardResponseStatus::UnknownStatus)
    }

    /// Gets the status from a status word (SW) for a select command.
    pub fn from_select_status(sw: u16) -> Self {
        SELECT_STATUS.get(&sw).copied().unwrap_or(HealthCardResponseStatus::UnknownStatus)
    }

    /// Gets the status from a status word (SW) for a verify secret command.
    pub fn from_verify_secret_status(sw: u16) -> Self {
        VERIFY_SECRET_STATUS.get(&sw).copied().unwrap_or(HealthCardResponseStatus::UnknownStatus)
    }

    /// Gets the status from a status word (SW) for an unlock EGK command.
    pub fn from_unlock_egk_status(sw: u16) -> Self {
        UNLOCK_EGK_STATUS.get(&sw).copied().unwrap_or(HealthCardResponseStatus::UnknownStatus)
    }

    /// Gets the status from a status word (SW) for a change reference data command.
    pub fn from_change_reference_data_status(sw: u16) -> Self {
        CHANGE_REFERENCE_DATA_STATUS.get(&sw).copied().unwrap_or(HealthCardResponseStatus::UnknownStatus)
    }

    /// Gets the status from a status word (SW) for a get random values command.
    pub fn from_get_random_values_status(sw: u16) -> Self {
        GET_RANDOM_VALUES_STATUS.get(&sw).copied().unwrap_or(HealthCardResponseStatus::UnknownStatus)
    }

    /// Check if the status indicates success.
    pub fn is_success(&self) -> bool {
        *self == HealthCardResponseStatus::Success
    }
}

lazy_static! {
    pub static ref GENERAL_AUTHENTICATE_STATUS: HashMap<u16, HealthCardResponseStatus> = {
        let mut map = HashMap::new();
        map.insert(0x0000, HealthCardResponseStatus::UnknownStatus);
        map.insert(0x9000, HealthCardResponseStatus::Success);
        map.insert(0x6300, HealthCardResponseStatus::AuthenticationFailure);
        map.insert(0x6400, HealthCardResponseStatus::ParameterMismatch);
        map.insert(0x6982, HealthCardResponseStatus::SecurityStatusNotSatisfied);
        map.insert(0x6983, HealthCardResponseStatus::KeyExpired);
        map.insert(0x6985, HealthCardResponseStatus::NoKeyReference);
        map.insert(0x6A80, HealthCardResponseStatus::NumberPreconditionWrong);
        map.insert(0x6A81, HealthCardResponseStatus::UnsupportedFunction);
        map.insert(0x6A88, HealthCardResponseStatus::KeyNotFound);
        map
    };

    pub static ref PIN_STATUS: HashMap<u16, HealthCardResponseStatus> = {
        let mut map = HashMap::new();
        map.insert(0x9000, HealthCardResponseStatus::Success);
        map.insert(0x62C1, HealthCardResponseStatus::TransportStatusTransportPin);
        map.insert(0x62C7, HealthCardResponseStatus::TransportStatusEmptyPin);
        map.insert(0x62D0, HealthCardResponseStatus::PasswordDisabled);
        map.insert(0x63C0, HealthCardResponseStatus::RetryCounterCount00);
        map.insert(0x63C1, HealthCardResponseStatus::RetryCounterCount01);
        map.insert(0x63C2, HealthCardResponseStatus::RetryCounterCount02);
        map.insert(0x63C3, HealthCardResponseStatus::RetryCounterCount03);
        map.insert(0x6982, HealthCardResponseStatus::SecurityStatusNotSatisfied);
        map.insert(0x6988, HealthCardResponseStatus::PasswordNotFound);
        map
    };

    pub static ref MANAGE_SECURITY_ENVIRONMENT_STATUS: HashMap<u16, HealthCardResponseStatus> = {
        let mut map = HashMap::new();
        map.insert(0x9000, HealthCardResponseStatus::Success);
        map.insert(0x6A81, HealthCardResponseStatus::UnsupportedFunction);
        map.insert(0x6A88, HealthCardResponseStatus::KeyNotFound);
        map
    };

    pub static ref PSO_COMPUTE_DIGITAL_SIGNATURE_STATUS: HashMap<u16, HealthCardResponseStatus> = {
        let mut map = HashMap::new();
        map.insert(0x9000, HealthCardResponseStatus::Success);
        map.insert(0x6400, HealthCardResponseStatus::KeyInvalid);
        map.insert(0x6982, HealthCardResponseStatus::SecurityStatusNotSatisfied);
        map.insert(0x6985, HealthCardResponseStatus::NoKeyReference);
        map.insert(0x6A81, HealthCardResponseStatus::UnsupportedFunction);
        map.insert(0x6A88, HealthCardResponseStatus::KeyNotFound);
        map
    };

    pub static ref READ_STATUS: HashMap<u16, HealthCardResponseStatus> = {
        let mut map = HashMap::new();
        map.insert(0x9000, HealthCardResponseStatus::Success);
        map.insert(0x6281, HealthCardResponseStatus::CorruptDataWarning);
        map.insert(0x6282, HealthCardResponseStatus::EndOfFileWarning);
        map.insert(0x6981, HealthCardResponseStatus::WrongFileType);
        map.insert(0x6982, HealthCardResponseStatus::SecurityStatusNotSatisfied);
        map.insert(0x6986, HealthCardResponseStatus::NoCurrentEf);
        map.insert(0x6A82, HealthCardResponseStatus::FileNotFound);
        map.insert(0x6B00, HealthCardResponseStatus::OffsetTooBig);
        map
    };

    pub static ref SELECT_STATUS: HashMap<u16, HealthCardResponseStatus> = {
        let mut map = HashMap::new();
        map.insert(0x9000, HealthCardResponseStatus::Success);
        map.insert(0x6283, HealthCardResponseStatus::FileDeactivated);
        map.insert(0x6285, HealthCardResponseStatus::FileTerminated);
        map.insert(0x6A82, HealthCardResponseStatus::FileNotFound);
        map.insert(0x6D00, HealthCardResponseStatus::InstructionNotSupported);
        map
    };

    pub static ref VERIFY_SECRET_STATUS: HashMap<u16, HealthCardResponseStatus> = {
        let mut map = HashMap::new();
        map.insert(0x9000, HealthCardResponseStatus::Success);
        map.insert(0x63C0, HealthCardResponseStatus::WrongSecretWarningCount00);
        map.insert(0x63C1, HealthCardResponseStatus::WrongSecretWarningCount01);
        map.insert(0x63C2, HealthCardResponseStatus::WrongSecretWarningCount02);
        map.insert(0x63C3, HealthCardResponseStatus::WrongSecretWarningCount03);
        map.insert(0x6581, HealthCardResponseStatus::MemoryFailure);
        map.insert(0x6982, HealthCardResponseStatus::SecurityStatusNotSatisfied);
        map.insert(0x6983, HealthCardResponseStatus::PasswordBlocked);
        map.insert(0x6985, HealthCardResponseStatus::PasswordNotUsable);
        map.insert(0x6988, HealthCardResponseStatus::PasswordNotFound);
        map
    };

    pub static ref UNLOCK_EGK_STATUS: HashMap<u16, HealthCardResponseStatus> = {
        let mut map = HashMap::new();
        map.insert(0x9000, HealthCardResponseStatus::Success);
        map.insert(0x6983, HealthCardResponseStatus::PukBlocked);
        map.insert(0x63C0, HealthCardResponseStatus::WrongSecretWarningCount00);
        map.insert(0x63C1, HealthCardResponseStatus::WrongSecretWarningCount01);
        map.insert(0x63C2, HealthCardResponseStatus::WrongSecretWarningCount02);
        map.insert(0x63C3, HealthCardResponseStatus::WrongSecretWarningCount03);
        map.insert(0x63C4, HealthCardResponseStatus::WrongSecretWarningCount04);
        map.insert(0x63C5, HealthCardResponseStatus::WrongSecretWarningCount05);
        map.insert(0x63C6, HealthCardResponseStatus::WrongSecretWarningCount06);
        map.insert(0x63C7, HealthCardResponseStatus::WrongSecretWarningCount07);
        map.insert(0x63C8, HealthCardResponseStatus::WrongSecretWarningCount08);
        map.insert(0x63C9, HealthCardResponseStatus::WrongSecretWarningCount09);
        map.insert(0x6581, HealthCardResponseStatus::MemoryFailure);
        map.insert(0x6982, HealthCardResponseStatus::SecurityStatusNotSatisfied);
        map.insert(0x6985, HealthCardResponseStatus::WrongPasswordLength);
        map.insert(0x6A88, HealthCardResponseStatus::PasswordNotFound);
        map
    };

    pub static ref CHANGE_REFERENCE_DATA_STATUS: HashMap<u16, HealthCardResponseStatus> = {
        let mut map = HashMap::new();
        map.insert(0x9000, HealthCardResponseStatus::Success);
        map.insert(0x63C0, HealthCardResponseStatus::WrongSecretWarningCount00);
        map.insert(0x63C1, HealthCardResponseStatus::WrongSecretWarningCount01);
        map.insert(0x63C2, HealthCardResponseStatus::WrongSecretWarningCount02);
        map.insert(0x63C3, HealthCardResponseStatus::WrongSecretWarningCount03); // oldSecret wrong
        map.insert(0x6581, HealthCardResponseStatus::MemoryFailure);
        map.insert(0x6982, HealthCardResponseStatus::SecurityStatusNotSatisfied);
        map.insert(0x6983, HealthCardResponseStatus::PasswordBlocked);
        map.insert(0x6985, HealthCardResponseStatus::WrongPasswordLength);
        map.insert(0x6A88, HealthCardResponseStatus::PasswordNotFound);
        map
    };

    pub static ref GET_RANDOM_VALUES_STATUS: HashMap<u16, HealthCardResponseStatus> = {
        let mut map = HashMap::new();
        map.insert(0x9000, HealthCardResponseStatus::Success);
        map.insert(0x6982, HealthCardResponseStatus::SecurityStatusNotSatisfied);
        map
    };
}

/// Extension trait to get the HealthCardResponseStatus from a status word
pub trait StatusWordExt {
    /// Get the HealthCardResponseStatus for a general authenticate command
    fn to_general_authenticate_status(&self) -> HealthCardResponseStatus;

    /// Get the HealthCardResponseStatus for a PIN-related command
    fn to_pin_status(&self) -> HealthCardResponseStatus;

    /// Get the HealthCardResponseStatus for a manage security environment command
    fn to_manage_security_environment_status(&self) -> HealthCardResponseStatus;

    /// Get the HealthCardResponseStatus for a PSO compute digital signature command
    fn to_pso_compute_digital_signature_status(&self) -> HealthCardResponseStatus;

    /// Get the HealthCardResponseStatus for a read command
    fn to_read_status(&self) -> HealthCardResponseStatus;

    /// Get the HealthCardResponseStatus for a select command
    fn to_select_status(&self) -> HealthCardResponseStatus;

    /// Get the HealthCardResponseStatus for a verify secret command
    fn to_verify_secret_status(&self) -> HealthCardResponseStatus;

    /// Get the HealthCardResponseStatus for an unlock EGK command
    fn to_unlock_egk_status(&self) -> HealthCardResponseStatus;

    /// Get the HealthCardResponseStatus for a change reference data command
    fn to_change_reference_data_status(&self) -> HealthCardResponseStatus;

    /// Get the HealthCardResponseStatus for a get random values command
    fn to_get_random_values_status(&self) -> HealthCardResponseStatus;
}

impl StatusWordExt for u16 {
    fn to_general_authenticate_status(&self) -> HealthCardResponseStatus {
        HealthCardResponseStatus::from_general_authenticate_status(*self)
    }

    fn to_pin_status(&self) -> HealthCardResponseStatus {
        HealthCardResponseStatus::from_pin_status(*self)
    }

    fn to_manage_security_environment_status(&self) -> HealthCardResponseStatus {
        HealthCardResponseStatus::from_manage_security_environment_status(*self)
    }

    fn to_pso_compute_digital_signature_status(&self) -> HealthCardResponseStatus {
        HealthCardResponseStatus::from_pso_compute_digital_signature_status(*self)
    }

    fn to_read_status(&self) -> HealthCardResponseStatus {
        HealthCardResponseStatus::from_read_status(*self)
    }

    fn to_select_status(&self) -> HealthCardResponseStatus {
        HealthCardResponseStatus::from_select_status(*self)
    }

    fn to_verify_secret_status(&self) -> HealthCardResponseStatus {
        HealthCardResponseStatus::from_verify_secret_status(*self)
    }

    fn to_unlock_egk_status(&self) -> HealthCardResponseStatus {
        HealthCardResponseStatus::from_unlock_egk_status(*self)
    }

    fn to_change_reference_data_status(&self) -> HealthCardResponseStatus {
        HealthCardResponseStatus::from_change_reference_data_status(*self)
    }

    fn to_get_random_values_status(&self) -> HealthCardResponseStatus {
        HealthCardResponseStatus::from_get_random_values_status(*self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_general_authenticate_status() {
        assert_eq!(
            HealthCardResponseStatus::from_general_authenticate_status(0x9000),
            HealthCardResponseStatus::Success
        );
        assert_eq!(
            HealthCardResponseStatus::from_general_authenticate_status(0x6300),
            HealthCardResponseStatus::AuthenticationFailure
        );
        assert_eq!(
            HealthCardResponseStatus::from_general_authenticate_status(0x1234),
            HealthCardResponseStatus::UnknownStatus
        );
    }

    #[test]
    fn test_status_word_ext() {
        let sw: u16 = 0x9000;
        assert_eq!(sw.to_general_authenticate_status(), HealthCardResponseStatus::Success);
        assert_eq!(sw.to_pin_status(), HealthCardResponseStatus::Success);
    }

    #[test]
    fn test_is_success() {
        assert!(HealthCardResponseStatus::Success.is_success());
        assert!(!HealthCardResponseStatus::FileNotFound.is_success());
    }
}
