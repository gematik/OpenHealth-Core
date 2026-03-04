// SPDX-FileCopyrightText: Copyright 2026 gematik GmbH
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

use super::channel::{CardChannel, CommandApdu, FfiCardChannelAdapter};
use super::exchange::{ExchangeError, HealthCardResponse};
use crate::card::{
    CardKey, CardKeyError, EncryptedPinFormat2, PasswordReference, PasswordReferenceError, PinBlockError, PsoAlgorithm,
};
use crate::command::apdu::ApduError;
use crate::command::change_reference_data_command::ChangeReferenceDataCommand;
use crate::command::general_authenticate_command::{GeneralAuthenticateCommand, GeneralAuthenticateCommandError};
use crate::command::get_pin_status_command::GetPinStatusCommand;
use crate::command::get_random_command::GetRandomValuesCommand;
use crate::command::health_card_command::{ExpectedLength, HealthCardCommand as CoreHealthCardCommand};
use crate::command::health_card_status::HealthCardResponseStatus;
use crate::command::internal_authenticate_command::InternalAuthenticateCommand;
use crate::command::list_public_key_command::ListPublicKeyCommand;
use crate::command::manage_security_environment_command::{
    ManageSecurityEnvironmentCommand, ManageSecurityEnvironmentCommandError,
};
use crate::command::pso_compute_digital_signature_command::PsoComputeDigitalSignatureCommand;
use crate::command::read_command::ReadCommand;
use crate::command::reset_retry_counter_command::ResetRetryCounterCommand;
use crate::command::reset_retry_counter_with_new_secret_command::ResetRetryCounterWithNewSecretCommand;
use crate::command::select_command::SelectCommand;
use crate::command::verify_pin_command::VerifyCommand;
use crate::command::CommandError;
use crate::exchange::channel::CardChannelExt;
use crate::identifier::{
    ApplicationIdentifier, ApplicationIdentifierError, FileIdentifier, FileIdentifierError, ShortFileIdentifier,
    ShortFileIdentifierError,
};
use std::sync::Arc;
use thiserror::Error;

/// UniFFI error type for command construction.
#[derive(Debug, Clone, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum CommandBuilderError {
    #[error("invalid argument: {reason}")]
    InvalidArgument { reason: String },
    #[error("ASN.1 encode error: {reason}")]
    Asn1Encode { reason: String },
    #[error("command composition error: {reason}")]
    Command { reason: String },
    #[error("pin block error: {reason}")]
    PinBlock { reason: String },
}

impl From<PasswordReferenceError> for CommandBuilderError {
    fn from(err: PasswordReferenceError) -> Self {
        Self::InvalidArgument { reason: err.to_string() }
    }
}

impl From<CardKeyError> for CommandBuilderError {
    fn from(err: CardKeyError) -> Self {
        Self::InvalidArgument { reason: err.to_string() }
    }
}

impl From<FileIdentifierError> for CommandBuilderError {
    fn from(err: FileIdentifierError) -> Self {
        Self::InvalidArgument { reason: err.to_string() }
    }
}

impl From<ShortFileIdentifierError> for CommandBuilderError {
    fn from(err: ShortFileIdentifierError) -> Self {
        Self::InvalidArgument { reason: err.to_string() }
    }
}

impl From<ApplicationIdentifierError> for CommandBuilderError {
    fn from(err: ApplicationIdentifierError) -> Self {
        Self::InvalidArgument { reason: err.to_string() }
    }
}

impl From<PinBlockError> for CommandBuilderError {
    fn from(err: PinBlockError) -> Self {
        Self::PinBlock { reason: err.to_string() }
    }
}

impl From<CommandError> for CommandBuilderError {
    fn from(err: CommandError) -> Self {
        Self::Command { reason: err.to_string() }
    }
}

impl From<ManageSecurityEnvironmentCommandError> for CommandBuilderError {
    fn from(err: ManageSecurityEnvironmentCommandError) -> Self {
        Self::Asn1Encode { reason: err.to_string() }
    }
}

impl From<GeneralAuthenticateCommandError> for CommandBuilderError {
    fn from(err: GeneralAuthenticateCommandError) -> Self {
        Self::Asn1Encode { reason: err.to_string() }
    }
}

fn car_from_bytes(bytes: Vec<u8>) -> Result<[u8; 8], CommandBuilderError> {
    bytes.try_into().map_err(|_| CommandBuilderError::InvalidArgument { reason: "CAR must be exactly 8 bytes".into() })
}

fn key_ref_from_bytes(bytes: Vec<u8>) -> Result<[u8; 12], CommandBuilderError> {
    bytes
        .try_into()
        .map_err(|_| CommandBuilderError::InvalidArgument { reason: "key_ref must be exactly 12 bytes".into() })
}
extern crate asn1;
fn encrypted_pin_from_bytes(bytes: Vec<u8>) -> Result<EncryptedPinFormat2, CommandBuilderError> {
    Ok(EncryptedPinFormat2::from_encrypted_bytes(bytes)?)
}

/// FFI wrapper for `HealthCardCommand`.
#[derive(uniffi::Object)]
pub struct HealthCardCommand {
    inner: CoreHealthCardCommand,
}

impl HealthCardCommand {
    fn new(inner: CoreHealthCardCommand) -> Self {
        Self { inner }
    }
}

#[uniffi::export]
impl HealthCardCommand {
    /// Encodes the command into a command APDU.
    pub fn to_apdu(&self, supports_extended_length: bool) -> Result<Arc<CommandApdu>, ApduError> {
        let apdu = self.inner.command_apdu(supports_extended_length)?;
        Ok(CommandApdu::from_core(apdu))
    }

    /// Maps a status word to the expected response status for this command.
    pub fn map_status(&self, sw: u16) -> HealthCardResponseStatus {
        self.inner.expected_status.get(&sw).copied().unwrap_or(HealthCardResponseStatus::UnknownStatus)
    }

    /// Executes the command on the given card channel and returns the mapped response.
    pub fn execute(&self, session: Arc<dyn CardChannel>) -> Result<HealthCardResponse, ExchangeError> {
        let mut adapter = FfiCardChannelAdapter::new(session);
        let response = adapter.execute_command(&self.inner)?;
        Ok(response.into())
    }

    /// Creates a SELECT command for root/parent selection.
    #[uniffi::constructor]
    pub fn select(select_parent_else_root: bool, read_first: bool) -> Self {
        Self::new(CoreHealthCardCommand::select(select_parent_else_root, read_first))
    }

    /// Creates a SELECT command for an AID.
    #[uniffi::constructor]
    pub fn select_aid(aid: Vec<u8>) -> Result<Self, CommandBuilderError> {
        let aid = ApplicationIdentifier::new(aid)?;
        Ok(Self::new(CoreHealthCardCommand::select_aid(&aid)))
    }

    /// Creates a SELECT command for an AID with options.
    #[uniffi::constructor]
    pub fn select_aid_with_options(
        aid: Vec<u8>,
        select_next_else_first_occurrence: bool,
        request_fcp: bool,
        fcp_length: i32,
    ) -> Result<Self, CommandBuilderError> {
        let aid = ApplicationIdentifier::new(aid)?;
        Ok(Self::new(CoreHealthCardCommand::select_aid_with_options(
            &aid,
            select_next_else_first_occurrence,
            request_fcp,
            fcp_length,
        )))
    }

    /// Creates a SELECT command for a FID.
    #[uniffi::constructor]
    pub fn select_fid(fid: u16, select_df_else_ef: bool) -> Result<Self, CommandBuilderError> {
        let fid = FileIdentifier::new(fid)?;
        Ok(Self::new(CoreHealthCardCommand::select_fid(&fid, select_df_else_ef)))
    }

    /// Creates a SELECT command for a FID with options.
    #[uniffi::constructor]
    pub fn select_fid_with_options(
        fid: u16,
        select_df_else_ef: bool,
        request_fcp: bool,
        fcp_length: i32,
    ) -> Result<Self, CommandBuilderError> {
        let fid = FileIdentifier::new(fid)?;
        Ok(Self::new(CoreHealthCardCommand::select_fid_with_options(&fid, select_df_else_ef, request_fcp, fcp_length)))
    }

    /// Creates a READ BINARY command (offset 0, any length).
    #[uniffi::constructor]
    pub fn read() -> Result<Self, CommandBuilderError> {
        Ok(Self::new(CoreHealthCardCommand::read()?))
    }

    /// Creates a READ BINARY command with offset.
    #[uniffi::constructor]
    pub fn read_with_offset(offset: i32) -> Result<Self, CommandBuilderError> {
        Ok(Self::new(CoreHealthCardCommand::read_with_offset(offset)?))
    }

    /// Creates a READ BINARY command with offset and exact expected length.
    #[uniffi::constructor]
    pub fn read_with_offset_and_length(offset: i32, expected_length: u32) -> Result<Self, CommandBuilderError> {
        let expected_length = expected_length as usize;
        Ok(Self::new(CoreHealthCardCommand::read_with_offset_and_length(
            offset,
            ExpectedLength::Exact(expected_length),
        )?))
    }

    /// Creates a READ BINARY command for an SFI (offset 0, any length).
    #[uniffi::constructor]
    pub fn read_sfi(sfi: u8) -> Result<Self, CommandBuilderError> {
        let sfi = ShortFileIdentifier::new(sfi)?;
        Ok(Self::new(CoreHealthCardCommand::read_sfi(sfi)?))
    }

    /// Creates a READ BINARY command for an SFI with offset.
    #[uniffi::constructor]
    pub fn read_sfi_with_offset(sfi: u8, offset: i32) -> Result<Self, CommandBuilderError> {
        let sfi = ShortFileIdentifier::new(sfi)?;
        Ok(Self::new(CoreHealthCardCommand::read_sfi_with_offset(sfi, offset)?))
    }

    /// Creates a READ BINARY command for an SFI with offset and exact expected length.
    #[uniffi::constructor]
    pub fn read_sfi_with_offset_and_length(
        sfi: u8,
        offset: i32,
        expected_length: u32,
    ) -> Result<Self, CommandBuilderError> {
        let sfi = ShortFileIdentifier::new(sfi)?;
        let expected_length = expected_length as usize;
        Ok(Self::new(CoreHealthCardCommand::read_sfi_with_offset_and_length(
            sfi,
            offset,
            ExpectedLength::Exact(expected_length),
        )?))
    }

    /// Creates a GET PIN STATUS command.
    #[uniffi::constructor]
    pub fn get_pin_status(password_id: u8, df_specific: bool) -> Result<Self, CommandBuilderError> {
        let password_reference = PasswordReference::new(password_id)?;
        Ok(Self::new(CoreHealthCardCommand::get_pin_status(&password_reference, df_specific)))
    }

    /// Creates a VERIFY PIN command with an encrypted PIN block (format 2).
    #[uniffi::constructor]
    pub fn verify_pin(password_id: u8, df_specific: bool, encrypted_pin: Vec<u8>) -> Result<Self, CommandBuilderError> {
        let password_reference = PasswordReference::new(password_id)?;
        let encrypted_pin = encrypted_pin_from_bytes(encrypted_pin)?;
        Ok(Self::new(CoreHealthCardCommand::verify_pin(&password_reference, df_specific, &encrypted_pin)))
    }

    /// Creates a CHANGE REFERENCE DATA command with encrypted secrets (format 2).
    #[uniffi::constructor]
    pub fn change_reference_data(
        password_id: u8,
        df_specific: bool,
        old_secret: Vec<u8>,
        new_secret: Vec<u8>,
    ) -> Result<Self, CommandBuilderError> {
        let password_reference = PasswordReference::new(password_id)?;
        let old_secret = encrypted_pin_from_bytes(old_secret)?;
        let new_secret = encrypted_pin_from_bytes(new_secret)?;
        Ok(Self::new(CoreHealthCardCommand::change_reference_data(
            &password_reference,
            df_specific,
            &old_secret,
            &new_secret,
        )))
    }

    /// Creates a RESET RETRY COUNTER command with encrypted PUK (format 2).
    #[uniffi::constructor]
    pub fn reset_retry_counter(password_id: u8, df_specific: bool, puk: Vec<u8>) -> Result<Self, CommandBuilderError> {
        let password_reference = PasswordReference::new(password_id)?;
        let puk = encrypted_pin_from_bytes(puk)?;
        Ok(Self::new(CoreHealthCardCommand::reset_retry_counter(&password_reference, df_specific, &puk)))
    }

    /// Creates a RESET RETRY COUNTER WITH NEW SECRET command with encrypted PUK and new secret.
    #[uniffi::constructor]
    pub fn reset_retry_counter_with_new_secret(
        password_id: u8,
        df_specific: bool,
        puk: Vec<u8>,
        new_secret: Vec<u8>,
    ) -> Result<Self, CommandBuilderError> {
        let password_reference = PasswordReference::new(password_id)?;
        let puk = encrypted_pin_from_bytes(puk)?;
        let new_secret = encrypted_pin_from_bytes(new_secret)?;
        Ok(Self::new(CoreHealthCardCommand::reset_retry_counter_with_new_secret(
            &password_reference,
            df_specific,
            &puk,
            &new_secret,
        )))
    }

    /// Creates a GET RANDOM VALUES command.
    #[uniffi::constructor]
    pub fn get_random_values(length: u32) -> Self {
        Self::new(CoreHealthCardCommand::get_random_values(length as usize))
    }

    /// Creates a LIST PUBLIC KEY command (proprietary GET DATA variant).
    #[uniffi::constructor]
    pub fn list_public_keys() -> Self {
        Self::new(CoreHealthCardCommand::list_public_keys())
    }

    /// Creates a PSO COMPUTE DIGITAL SIGNATURE command.
    #[uniffi::constructor]
    pub fn pso_compute_digital_signature(data_to_be_signed: Vec<u8>) -> Self {
        Self::new(CoreHealthCardCommand::pso_compute_digital_signature(&data_to_be_signed))
    }

    /// Creates a PSO COMPUTE DIGITAL SIGNATURE command with CVC value field.
    #[uniffi::constructor]
    pub fn pso_compute_digital_signature_cvc(data_to_be_signed: Vec<u8>) -> Self {
        Self::new(CoreHealthCardCommand::pso_compute_digital_signature_cvc(&data_to_be_signed))
    }

    /// Creates a MANAGE SECURITY ENVIRONMENT command for external authentication without curves.
    #[uniffi::constructor]
    pub fn manage_sec_env_without_curves(
        password_id: u8,
        df_specific: bool,
        oid: Vec<u8>,
    ) -> Result<Self, CommandBuilderError> {
        let password_reference = PasswordReference::new(password_id)?;
        Ok(Self::new(CoreHealthCardCommand::manage_sec_env_without_curves(&password_reference, df_specific, &oid)?))
    }

    /// Creates a MANAGE SECURITY ENVIRONMENT command for signing.
    #[uniffi::constructor]
    pub fn manage_sec_env_for_signing(
        pso_algorithm: PsoAlgorithm,
        key_id: u8,
        df_specific: bool,
    ) -> Result<Self, CommandBuilderError> {
        let key = CardKey::new(key_id)?;
        Ok(Self::new(CoreHealthCardCommand::manage_sec_env_for_signing(pso_algorithm, &key, df_specific)?))
    }

    /// Creates a MANAGE SECURITY ENVIRONMENT command for selecting a private key + algorithm.
    #[uniffi::constructor]
    pub fn manage_sec_env_select_private_key(key_ref: u8, algorithm_id: u8) -> Result<Self, CommandBuilderError> {
        Ok(Self::new(CoreHealthCardCommand::manage_sec_env_select_private_key(key_ref, algorithm_id)?))
    }

    /// Creates a MANAGE SECURITY ENVIRONMENT command for setting the signature key reference (CAR).
    #[uniffi::constructor]
    pub fn manage_sec_env_set_signature_key_reference(key_ref: Vec<u8>) -> Result<Self, CommandBuilderError> {
        Ok(Self::new(CoreHealthCardCommand::manage_sec_env_set_signature_key_reference(&key_ref)?))
    }

    /// Creates a MANAGE SECURITY ENVIRONMENT command for CV certificate verification key selection.
    #[uniffi::constructor]
    pub fn manage_sec_env_for_verify_certificate(car: Vec<u8>) -> Result<Self, CommandBuilderError> {
        let car = car_from_bytes(car)?;
        Ok(Self::new(CoreHealthCardCommand::manage_sec_env_set_signature_key_reference(&car)?))
    }

    /// Creates a GENERAL AUTHENTICATE command (empty data).
    #[uniffi::constructor]
    pub fn general_authenticate(command_chaining: bool) -> Result<Self, CommandBuilderError> {
        Ok(Self::new(CoreHealthCardCommand::general_authenticate(command_chaining)?))
    }

    /// Creates a GENERAL AUTHENTICATE command with data.
    #[uniffi::constructor]
    pub fn general_authenticate_with_data(
        command_chaining: bool,
        data: Vec<u8>,
        tag_no: u8,
    ) -> Result<Self, CommandBuilderError> {
        Ok(Self::new(CoreHealthCardCommand::general_authenticate_with_data(command_chaining, &data, tag_no)?))
    }

    /// Creates a GENERAL AUTHENTICATE command for mutual authentication step 1.
    #[uniffi::constructor]
    pub fn general_authenticate_mutual_authentication_step1(key_ref: Vec<u8>) -> Result<Self, CommandBuilderError> {
        let key_ref = key_ref_from_bytes(key_ref)?;
        Ok(Self::new(CoreHealthCardCommand::general_authenticate_mutual_authentication_step1(&key_ref)?))
    }

    /// Creates a GENERAL AUTHENTICATE command for mutual ELC authentication step 2.
    #[uniffi::constructor]
    pub fn general_authenticate_elc_step2(ephemeral_pk_opponent: Vec<u8>) -> Result<Self, CommandBuilderError> {
        Ok(Self::new(CoreHealthCardCommand::general_authenticate_elc_step2(&ephemeral_pk_opponent)?))
    }

    /// Creates an INTERNAL AUTHENTICATE command.
    #[uniffi::constructor]
    pub fn internal_authenticate(challenge: Vec<u8>) -> Self {
        Self::new(CoreHealthCardCommand::internal_authenticate(&challenge))
    }
}

/// Generates the host-side ephemeral public key for GA step 2 (ELC), based on the curve in the CVC.
#[uniffi::export]
pub fn generate_elc_ephemeral_public_key(cvc: Vec<u8>) -> Result<Vec<u8>, ExchangeError> {
    crate::exchange::generate_elc_ephemeral_public_key_from_cvc(&cvc).map_err(ExchangeError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use asn1::cv_certificate::CVCertificate;
    use asn1::decoder::extract_context_values;
    use std::fs;
    use std::path::PathBuf;

    fn load_fixture(name: &str) -> Vec<u8> {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.pop();
        path.pop();
        path.push("test-vectors");
        path.push("cvc-chain");
        path.push("pki_cvc_g2_input");
        path.push("Atos_CVC-Root-CA");
        path.push(name);
        fs::read(&path).expect("fixture should be readable")
    }

    fn expected_point_len(cvc: &CVCertificate) -> usize {
        let key_data = &cvc.body.public_key.key_data;
        let mut values = extract_context_values(key_data, 6).expect("context tag 6 present");
        values.pop().expect("public key point").len()
    }

    #[test]
    fn car_from_bytes_accepts_exact_len() {
        let bytes = vec![0xA5; 8];
        let car = car_from_bytes(bytes.clone()).expect("CAR should be accepted");
        assert_eq!(car, [0xA5; 8]);
    }

    #[test]
    fn car_from_bytes_rejects_wrong_len() {
        let result = car_from_bytes(vec![0x00; 7]);
        assert!(matches!(result, Err(CommandBuilderError::InvalidArgument { .. })));
    }

    #[test]
    fn key_ref_from_bytes_accepts_exact_len() {
        let bytes = vec![0x5A; 12];
        let key_ref = key_ref_from_bytes(bytes.clone()).expect("key_ref should be accepted");
        assert_eq!(key_ref, [0x5A; 12]);
    }

    #[test]
    fn key_ref_from_bytes_rejects_wrong_len() {
        let result = key_ref_from_bytes(vec![0x00; 11]);
        assert!(matches!(result, Err(CommandBuilderError::InvalidArgument { .. })));
    }

    #[test]
    fn generate_elc_ephemeral_public_key_matches_curve_length() {
        let cvc_bytes = load_fixture("DEGXX820214.cvc");
        let certificate = CVCertificate::parse(&cvc_bytes).expect("valid CVC");

        let expected_len = expected_point_len(&certificate);
        let pk = generate_elc_ephemeral_public_key(cvc_bytes).expect("key generation succeeds");

        assert_eq!(pk.len(), expected_len);
    }

    #[test]
    fn generate_elc_ephemeral_public_key_rejects_invalid_cvc() {
        let result = generate_elc_ephemeral_public_key(Vec::new());
        assert!(result.is_err());
    }
}
