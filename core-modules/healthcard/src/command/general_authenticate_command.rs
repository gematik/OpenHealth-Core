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

use openhealth_asn1::encoder::Asn1Encoder;
use openhealth_asn1::error::Asn1EncoderError;
use openhealth_asn1::tag::TagNumberExt;
use thiserror::Error;

use crate::command::health_card_command::{ExpectedLength, HealthCardCommand};
use crate::command::health_card_status::GENERAL_AUTHENTICATE_STATUS;

/// CLA byte for command chaining
const CLA_COMMAND_CHAINING: u8 = 0x10;
/// CLA byte for no command chaining
const CLA_NO_COMMAND_CHAINING: u8 = 0x00;
/// INS byte for the GENERAL AUTHENTICATE command
const INS: u8 = 0x86;
/// P1 and P2 parameter (no meaning)
const NO_MEANING: u8 = 0x00;
/// ASN.1 tag for GENERAL AUTHENTICATE (DO 7C)
const GENERAL_AUTHENTICATE_TAG: u8 = 28;
/// ASN.1 tag for mutual authentication step 1 key reference (DO C3)
const MUTUAL_AUTHENTICATION_KEY_REF_TAG: u8 = 3;
/// ASN.1 tag for PACE key agreement data (DO 81)
const PACE_KEY_AGREEMENT_TAG: u8 = 1;
/// ASN.1 tag for PACE ephemeral public key 2 (DO 83)
const PACE_EPHEMERAL_KEY2_TAG: u8 = 3;
/// ASN.1 tag for PACE mutual auth key 1 / ELC step 2 (DO 85)
const PACE_MUTUAL_KEY1_TAG: u8 = 5;

#[derive(Debug, Error)]
pub enum GeneralAuthenticateCommandError {
    #[error("Failed to encode GENERAL AUTHENTICATE command: {0}")]
    Asn1Encoding(#[from] Asn1EncoderError),
}

type GeneralAuthenticateResult<T> = Result<T, GeneralAuthenticateCommandError>;

/// Extension trait for HealthCardCommand to provide GENERAL AUTHENTICATE commands
pub trait GeneralAuthenticateCommand {
    /// Creates a HealthCardCommand for the GENERAL AUTHENTICATE command
    /// UseCase: gemSpec_COS_3.14.0#14.7.2.1.1 PACE for end-user cards, Step 1a
    ///
    /// # Arguments
    /// * `command_chaining` - true for command chaining false if not
    fn general_authenticate(command_chaining: bool) -> GeneralAuthenticateResult<HealthCardCommand>;

    /// Creates a HealthCardCommand for the GENERAL AUTHENTICATE command
    /// UseCase: gemSpec_COS_3.14.0#14.7.2.1.1 PACE for end-user cards, Step 2a (tagNo 1), 3a (3), 5a (5)
    ///
    /// # Arguments
    /// * `command_chaining` - true for command chaining false if not
    /// * `data` - byte vector with data
    /// * `tag_no` - tag number for the ASN.1 encoding
    fn general_authenticate_with_data(
        command_chaining: bool,
        data: &[u8],
        tag_no: u8,
    ) -> GeneralAuthenticateResult<HealthCardCommand>;

    /// Creates a HealthCardCommand for GENERAL AUTHENTICATE
    /// UseCase: gemSpec_COS_3.14.0#14.7.2.2.1 mutual ELC authentication, Step 1.
    ///
    /// # Arguments
    /// * `key_ref` - 12-byte public authentication key reference from the CV certificate.
    fn general_authenticate_mutual_authentication_step1(
        key_ref: &[u8; 12],
    ) -> GeneralAuthenticateResult<HealthCardCommand>;

    /// Creates a HealthCardCommand for the GENERAL AUTHENTICATE command
    /// UseCase: gemSpec_COS_3.14.0#14.7.2.1.1 PACE end-user card, Step 1a.
    fn general_authenticate_pace_end_user_step1() -> GeneralAuthenticateResult<HealthCardCommand>;

    /// Creates a HealthCardCommand for the GENERAL AUTHENTICATE command
    /// UseCase: gemSpec_COS_3.14.0#14.7.2.1.2 PACE end-user card, Step 2a.
    fn general_authenticate_pace_end_user_step2(pk1_pcd: &[u8]) -> GeneralAuthenticateResult<HealthCardCommand>;

    /// Creates a HealthCardCommand for the GENERAL AUTHENTICATE command
    /// UseCase: gemSpec_COS_3.14.0#14.7.2.1.3 PACE end-user card, Step 3a.
    fn general_authenticate_pace_end_user_step3(pk2_pcd: &[u8]) -> GeneralAuthenticateResult<HealthCardCommand>;

    /// Creates a HealthCardCommand for the GENERAL AUTHENTICATE command
    /// UseCase: gemSpec_COS_3.14.0#14.7.2.1.4 PACE end-user card, Step 4a.
    fn general_authenticate_pace_end_user_step4(tpcd: &[u8; 8]) -> GeneralAuthenticateResult<HealthCardCommand>;

    /// Creates a HealthCardCommand for the GENERAL AUTHENTICATE command
    /// UseCase: gemSpec_COS_3.14.0#14.7.2.2.2 mutual ELC authentication, Step 2.
    fn general_authenticate_elc_step2(ephemeral_pk_opponent: &[u8]) -> GeneralAuthenticateResult<HealthCardCommand>;
}

impl GeneralAuthenticateCommand for HealthCardCommand {
    fn general_authenticate(command_chaining: bool) -> GeneralAuthenticateResult<HealthCardCommand> {
        let cla = if command_chaining { CLA_COMMAND_CHAINING } else { CLA_NO_COMMAND_CHAINING };

        let data = Asn1Encoder::write_nonzeroizing(|w| -> Result<(), Asn1EncoderError> {
            w.write_tagged_object(GENERAL_AUTHENTICATE_TAG.application_tag().constructed(), |_inner| Ok(()))
        })?;

        Ok(HealthCardCommand::new(
            GENERAL_AUTHENTICATE_STATUS.clone(),
            cla,
            INS,
            NO_MEANING,
            NO_MEANING,
            Some(data),
            Some(ExpectedLength::Any),
        ))
    }

    fn general_authenticate_with_data(
        command_chaining: bool,
        data: &[u8],
        tag_no: u8,
    ) -> GeneralAuthenticateResult<HealthCardCommand> {
        let cla = if command_chaining { CLA_COMMAND_CHAINING } else { CLA_NO_COMMAND_CHAINING };

        let data_to_write = data.to_vec();
        let encoded_data = Asn1Encoder::write_zeroizing(|w| {
            w.write_tagged_object(GENERAL_AUTHENTICATE_TAG.application_tag().constructed(), |inner| {
                inner.write_tagged_object(tag_no.context_tag(), |innermost| -> Result<(), Asn1EncoderError> {
                    innermost.write_bytes(&data_to_write);
                    Ok(())
                })
            })
        })?;

        Ok(HealthCardCommand::new(
            GENERAL_AUTHENTICATE_STATUS.clone(),
            cla,
            INS,
            NO_MEANING,
            NO_MEANING,
            Some(encoded_data),
            Some(ExpectedLength::Any),
        ))
    }

    fn general_authenticate_mutual_authentication_step1(
        key_ref: &[u8; 12],
    ) -> GeneralAuthenticateResult<HealthCardCommand> {
        let data = Asn1Encoder::write_zeroizing(|w| {
            w.write_tagged_object(GENERAL_AUTHENTICATE_TAG.application_tag().constructed(), |inner| {
                inner.write_tagged_object(
                    MUTUAL_AUTHENTICATION_KEY_REF_TAG.private_tag(),
                    |innermost| -> Result<(), Asn1EncoderError> {
                        innermost.write_bytes(key_ref);
                        Ok(())
                    },
                )
            })
        })?;

        Ok(HealthCardCommand::new(
            GENERAL_AUTHENTICATE_STATUS.clone(),
            CLA_COMMAND_CHAINING,
            INS,
            NO_MEANING,
            NO_MEANING,
            Some(data),
            Some(ExpectedLength::Any),
        ))
    }

    fn general_authenticate_pace_end_user_step1() -> GeneralAuthenticateResult<HealthCardCommand> {
        let data = Asn1Encoder::write_nonzeroizing(|w| -> Result<(), Asn1EncoderError> {
            w.write_tagged_object(GENERAL_AUTHENTICATE_TAG.application_tag().constructed(), |_inner| Ok(()))
        })?;

        Ok(HealthCardCommand::new(
            GENERAL_AUTHENTICATE_STATUS.clone(),
            CLA_COMMAND_CHAINING,
            INS,
            NO_MEANING,
            NO_MEANING,
            Some(data),
            Some(ExpectedLength::Any),
        ))
    }

    fn general_authenticate_pace_end_user_step2(pk1_pcd: &[u8]) -> GeneralAuthenticateResult<HealthCardCommand> {
        let data = Asn1Encoder::write_zeroizing(|w| {
            w.write_tagged_object(GENERAL_AUTHENTICATE_TAG.application_tag().constructed(), |inner| {
                inner.write_tagged_object(
                    PACE_KEY_AGREEMENT_TAG.context_tag(),
                    |innermost| -> Result<(), Asn1EncoderError> {
                        innermost.write_bytes(pk1_pcd);
                        Ok(())
                    },
                )
            })
        })?;

        Ok(HealthCardCommand::new(
            GENERAL_AUTHENTICATE_STATUS.clone(),
            CLA_COMMAND_CHAINING,
            INS,
            NO_MEANING,
            NO_MEANING,
            Some(data),
            Some(ExpectedLength::Any),
        ))
    }

    fn general_authenticate_pace_end_user_step3(pk2_pcd: &[u8]) -> GeneralAuthenticateResult<HealthCardCommand> {
        let data = Asn1Encoder::write_zeroizing(|w| {
            w.write_tagged_object(GENERAL_AUTHENTICATE_TAG.application_tag().constructed(), |inner| {
                inner.write_tagged_object(
                    PACE_EPHEMERAL_KEY2_TAG.context_tag(),
                    |innermost| -> Result<(), Asn1EncoderError> {
                        innermost.write_bytes(pk2_pcd);
                        Ok(())
                    },
                )
            })
        })?;

        Ok(HealthCardCommand::new(
            GENERAL_AUTHENTICATE_STATUS.clone(),
            CLA_COMMAND_CHAINING,
            INS,
            NO_MEANING,
            NO_MEANING,
            Some(data),
            Some(ExpectedLength::Any),
        ))
    }

    fn general_authenticate_pace_end_user_step4(tpcd: &[u8; 8]) -> GeneralAuthenticateResult<HealthCardCommand> {
        let data = Asn1Encoder::write_zeroizing(|w| {
            w.write_tagged_object(GENERAL_AUTHENTICATE_TAG.application_tag().constructed(), |inner| {
                inner.write_tagged_object(
                    PACE_MUTUAL_KEY1_TAG.context_tag(),
                    |innermost| -> Result<(), Asn1EncoderError> {
                        innermost.write_bytes(tpcd);
                        Ok(())
                    },
                )
            })
        })?;

        Ok(HealthCardCommand::new(
            GENERAL_AUTHENTICATE_STATUS.clone(),
            CLA_NO_COMMAND_CHAINING,
            INS,
            NO_MEANING,
            NO_MEANING,
            Some(data),
            Some(ExpectedLength::Any),
        ))
    }

    fn general_authenticate_elc_step2(ephemeral_pk_opponent: &[u8]) -> GeneralAuthenticateResult<HealthCardCommand> {
        let data = Asn1Encoder::write_zeroizing(|w| {
            w.write_tagged_object(GENERAL_AUTHENTICATE_TAG.application_tag().constructed(), |inner| {
                inner.write_tagged_object(
                    PACE_MUTUAL_KEY1_TAG.context_tag(),
                    |innermost| -> Result<(), Asn1EncoderError> {
                        innermost.write_bytes(ephemeral_pk_opponent);
                        Ok(())
                    },
                )
            })
        })?;

        Ok(HealthCardCommand::new(
            GENERAL_AUTHENTICATE_STATUS.clone(),
            CLA_NO_COMMAND_CHAINING,
            INS,
            NO_MEANING,
            NO_MEANING,
            Some(data),
            None,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::apdu::EXPECTED_LENGTH_WILDCARD_SHORT;
    use openhealth_asn1::maybe_zeroizing_vec::ZeroizingOption;
    use openhealth_asn1::tag::{Asn1Class, Asn1Form};

    #[test]
    fn test_general_authenticate_without_chaining() {
        let command = HealthCardCommand::general_authenticate(false).unwrap();

        assert_eq!(command.cla, CLA_NO_COMMAND_CHAINING);
        assert_eq!(command.ins, INS);
        assert_eq!(command.p1, NO_MEANING);
        assert_eq!(command.p2, NO_MEANING);
        assert_eq!(command.ne, Some(ExpectedLength::Any));

        let data = command.data.unwrap();

        assert_eq!(data[0], GENERAL_AUTHENTICATE_TAG | (Asn1Class::Application | Asn1Form::Constructed));
        assert_eq!(data[1], 0);
        assert_eq!(data.len(), 2);
    }

    #[test]
    fn test_general_authenticate_with_chaining() {
        let command = HealthCardCommand::general_authenticate(true).unwrap();

        assert_eq!(command.cla, CLA_COMMAND_CHAINING);

        assert_eq!(command.ins, INS);
        assert_eq!(command.p1, NO_MEANING);
        assert_eq!(command.p2, NO_MEANING);
        assert_eq!(command.ne, Some(ExpectedLength::Any));

        let data = command.data.unwrap();
        assert_eq!(data[0], GENERAL_AUTHENTICATE_TAG | (Asn1Class::Application | Asn1Form::Constructed));
        assert_eq!(data[1], 0);
        assert_eq!(data.len(), 2);
    }

    #[test]
    fn test_general_authenticate_with_data_tag1() {
        let test_data = vec![0x01, 0x02, 0x03, 0x04];
        let command = HealthCardCommand::general_authenticate_with_data(false, &test_data, 1).unwrap();

        assert_eq!(command.cla, CLA_NO_COMMAND_CHAINING);
        assert_eq!(command.ins, INS);
        assert_eq!(command.p1, NO_MEANING);
        assert_eq!(command.p2, NO_MEANING);
        assert_eq!(command.ne, Some(ExpectedLength::Any));

        let data = command.data.unwrap();

        assert_eq!(data[0], GENERAL_AUTHENTICATE_TAG | (Asn1Class::Application | Asn1Form::Constructed));
        assert_eq!(data[1], 6);
        assert_eq!(data[2], u8::from(Asn1Class::ContextSpecific) | 1);
        assert_eq!(data[3], test_data.len() as u8);
        assert_eq!(&data[4..8], &test_data);
        assert_eq!(data.get_zeroizing_option(), ZeroizingOption::Zeroes);
    }

    #[test]
    fn test_general_authenticate_with_data_tag3() {
        let test_data = vec![0x05, 0x06, 0x07, 0x08, 0x09];
        let command = HealthCardCommand::general_authenticate_with_data(true, &test_data, 3).unwrap();

        assert_eq!(command.cla, CLA_COMMAND_CHAINING);

        let data = command.data.unwrap();

        assert_eq!(data[0], GENERAL_AUTHENTICATE_TAG | (Asn1Class::Application | Asn1Form::Constructed));
        assert_eq!(data[1], 7); // tag (1) + length (1) + data (5)
        assert_eq!(data[2], u8::from(Asn1Class::ContextSpecific) | 3);
        assert_eq!(data[3], test_data.len() as u8);
        assert_eq!(&data[4..9], &test_data);
    }

    #[test]
    fn test_general_authenticate_with_data_tag5() {
        let test_data = vec![0x0A, 0x0B, 0x0C];
        let command = HealthCardCommand::general_authenticate_with_data(false, &test_data, 5).unwrap();
        let data = command.data.unwrap();
        assert_eq!(data[0], GENERAL_AUTHENTICATE_TAG | (Asn1Class::Application | Asn1Form::Constructed));
        assert_eq!(data[1], 5);
        assert_eq!(data[2], u8::from(Asn1Class::ContextSpecific) | 5);
        assert_eq!(data[3], test_data.len() as u8);
        assert_eq!(&data[4..7], &test_data);
    }

    #[test]
    fn test_general_authenticate_with_data_tag5_apdu_encoding() {
        let mac = [0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        let command = HealthCardCommand::general_authenticate_with_data(false, &mac, 5).unwrap();
        let apdu = command.command_apdu(false).unwrap();

        let expected = vec![
            0x00, 0x86, 0x00, 0x00, 0x0C, 0x7C, 0x0A, 0x85, 0x08, 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE, 0x00,
        ];
        assert_eq!(apdu.as_bytes(), expected);
    }

    #[test]
    fn test_command_apdu_generation() {
        let command = HealthCardCommand::general_authenticate(false).unwrap();
        let apdu = command.command_apdu(false).unwrap();

        assert_eq!(apdu.cla(), command.cla);
        assert_eq!(apdu.ins(), command.ins);
        assert_eq!(apdu.p1(), command.p1);
        assert_eq!(apdu.p2(), command.p2);
        assert_eq!(apdu.as_data().unwrap(), &command.data.as_ref().unwrap()[..]);
        assert_eq!(apdu.expected_length(), Some(EXPECTED_LENGTH_WILDCARD_SHORT));
    }

    #[test]
    fn test_with_large_data() {
        let mut large_data = Vec::new();
        for i in 0..128 {
            large_data.push(i);
        }
        let command = HealthCardCommand::general_authenticate_with_data(false, &large_data, 1).unwrap();
        let data = command.data.unwrap();

        assert_eq!(data[0], GENERAL_AUTHENTICATE_TAG | (Asn1Class::Application | Asn1Form::Constructed));
        assert_eq!(data[1], 0x81);
        assert_eq!(data[2], 0x83);
        assert_eq!(data[3], u8::from(Asn1Class::ContextSpecific) | 1);
        assert_eq!(data[4], 0x81);
        assert_eq!(data[5], 0x80);

        assert_eq!(&data[6..(6 + 128)], &large_data[..]);
        assert_eq!(data.len(), 134);
    }

    #[test]
    fn test_general_authenticate_mutual_authentication_step1() {
        let key_ref = *b"0123456789AB";
        let command = HealthCardCommand::general_authenticate_mutual_authentication_step1(&key_ref).unwrap();

        assert_eq!(command.cla, CLA_COMMAND_CHAINING);
        assert_eq!(command.ins, INS);
        assert_eq!(command.p1, NO_MEANING);
        assert_eq!(command.p2, NO_MEANING);
        assert_eq!(command.ne, Some(ExpectedLength::Any));

        let data = command.data.unwrap();
        assert_eq!(data[0], GENERAL_AUTHENTICATE_TAG | (Asn1Class::Application | Asn1Form::Constructed));
        assert_eq!(data[1], 0x0E);
        assert_eq!(data[2], u8::from(Asn1Class::Private) | MUTUAL_AUTHENTICATION_KEY_REF_TAG);
        assert_eq!(data[3], 0x0C);
        assert_eq!(&data[4..16], &key_ref);
        assert_eq!(data.len(), 16);
    }

    #[test]
    fn test_general_authenticate_pace_end_user_step1() {
        let command = HealthCardCommand::general_authenticate_pace_end_user_step1().unwrap();

        assert_eq!(command.cla, CLA_COMMAND_CHAINING);
        assert_eq!(command.ne, Some(ExpectedLength::Any));

        let data = command.data.unwrap();
        assert_eq!(data.as_ref(), &[0x7C, 0x00]);
    }

    #[test]
    fn test_general_authenticate_pace_end_user_step2() {
        let pk1 = vec![0xAA, 0xBB, 0xCC];
        let command = HealthCardCommand::general_authenticate_pace_end_user_step2(&pk1).unwrap();

        assert_eq!(command.cla, CLA_COMMAND_CHAINING);
        assert_eq!(command.ne, Some(ExpectedLength::Any));

        let data = command.data.unwrap();
        assert_eq!(data[0], GENERAL_AUTHENTICATE_TAG | (Asn1Class::Application | Asn1Form::Constructed));
        assert_eq!(data[2], u8::from(Asn1Class::ContextSpecific) | PACE_KEY_AGREEMENT_TAG);
        assert_eq!(&data[4..7], &pk1);
    }

    #[test]
    fn test_general_authenticate_pace_end_user_step3() {
        let pk2 = vec![0x01, 0x02];
        let command = HealthCardCommand::general_authenticate_pace_end_user_step3(&pk2).unwrap();

        assert_eq!(command.cla, CLA_COMMAND_CHAINING);
        assert_eq!(command.ne, Some(ExpectedLength::Any));

        let data = command.data.unwrap();
        assert_eq!(data[2], u8::from(Asn1Class::ContextSpecific) | PACE_EPHEMERAL_KEY2_TAG);
        assert_eq!(&data[4..6], &pk2);
    }

    #[test]
    fn test_general_authenticate_pace_end_user_step4() {
        let tpcd = *b"TPCDTEST";
        let command = HealthCardCommand::general_authenticate_pace_end_user_step4(&tpcd).unwrap();

        assert_eq!(command.cla, CLA_NO_COMMAND_CHAINING);
        assert_eq!(command.ne, Some(ExpectedLength::Any));

        let data = command.data.unwrap();
        assert_eq!(data[2], u8::from(Asn1Class::ContextSpecific) | PACE_MUTUAL_KEY1_TAG);
        assert_eq!(data[3], 0x08);
        assert_eq!(&data[4..12], &tpcd);
    }

    #[test]
    fn test_general_authenticate_elc_step2() {
        let pk_opponent = vec![0x10, 0x11, 0x12];
        let command = HealthCardCommand::general_authenticate_elc_step2(&pk_opponent).unwrap();

        assert_eq!(command.cla, CLA_NO_COMMAND_CHAINING);
        assert_eq!(command.ne, None);

        let data = command.data.unwrap();
        assert_eq!(data[2], u8::from(Asn1Class::ContextSpecific) | PACE_MUTUAL_KEY1_TAG);
        assert_eq!(&data[4..7], &pk_opponent);
        assert_eq!(data.get_zeroizing_option(), ZeroizingOption::Zeroes);
    }
}
