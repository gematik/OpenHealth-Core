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

use crate::command::apdu::EXPECTED_LENGTH_WILDCARD_SHORT;
use asn1::encoder::Asn1Encoder;
use asn1::error::Asn1EncoderError;
use asn1::tag::TagNumberExt;
use thiserror::Error;

use crate::command::health_card_command::HealthCardCommand;
use crate::command::health_card_status::GENERAL_AUTHENTICATE_STATUS;

/// CLA byte for command chaining
const CLA_COMMAND_CHAINING: u8 = 0x10;
/// CLA byte for no command chaining
const CLA_NO_COMMAND_CHAINING: u8 = 0x00;
/// INS byte for the GENERAL AUTHENTICATE command
const INS: u8 = 0x86;
/// P1 and P2 parameter (no meaning)
const NO_MEANING: u8 = 0x00;
/// ASN.1 tag for GENERAL AUTHENTICATE
const GENERAL_AUTHENTICATE_TAG: u8 = 28;

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
}

impl GeneralAuthenticateCommand for HealthCardCommand {
    fn general_authenticate(command_chaining: bool) -> GeneralAuthenticateResult<HealthCardCommand> {
        let cla = if command_chaining { CLA_COMMAND_CHAINING } else { CLA_NO_COMMAND_CHAINING };

        let data = Asn1Encoder::write(|w| -> Result<(), Asn1EncoderError> {
            w.write_tagged_object(GENERAL_AUTHENTICATE_TAG.application_tag().constructed(), |_inner| Ok(()))
        })?;

        Ok(HealthCardCommand {
            expected_status: GENERAL_AUTHENTICATE_STATUS.clone(),
            cla,
            ins: INS,
            p1: NO_MEANING,
            p2: NO_MEANING,
            data: Some(data),
            ne: Some(EXPECTED_LENGTH_WILDCARD_SHORT),
        })
    }

    fn general_authenticate_with_data(
        command_chaining: bool,
        data: &[u8],
        tag_no: u8,
    ) -> GeneralAuthenticateResult<HealthCardCommand> {
        let cla = if command_chaining { CLA_COMMAND_CHAINING } else { CLA_NO_COMMAND_CHAINING };

        let data_to_write = data.to_vec();
        let encoded_data = Asn1Encoder::write(|w| {
            w.write_tagged_object(GENERAL_AUTHENTICATE_TAG.application_tag().constructed(), |inner| {
                inner.write_tagged_object(tag_no.context_tag(), |innermost| -> Result<(), Asn1EncoderError> {
                    innermost.write_bytes(&data_to_write);
                    Ok(())
                })
            })
        })?;

        Ok(HealthCardCommand {
            expected_status: GENERAL_AUTHENTICATE_STATUS.clone(),
            cla,
            ins: INS,
            p1: NO_MEANING,
            p2: NO_MEANING,
            data: Some(encoded_data),
            ne: Some(EXPECTED_LENGTH_WILDCARD_SHORT),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::command::apdu::CardCommandApdu;
    use asn1::tag::{Asn1Class, Asn1Form};

    #[test]
    fn test_general_authenticate_without_chaining() {
        let command = HealthCardCommand::general_authenticate(false).unwrap();

        assert_eq!(command.cla, CLA_NO_COMMAND_CHAINING);
        assert_eq!(command.ins, INS);
        assert_eq!(command.p1, NO_MEANING);
        assert_eq!(command.p2, NO_MEANING);
        assert_eq!(command.ne, Some(EXPECTED_LENGTH_WILDCARD_SHORT));

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
        assert_eq!(command.ne, Some(EXPECTED_LENGTH_WILDCARD_SHORT));

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
        assert_eq!(command.ne, Some(EXPECTED_LENGTH_WILDCARD_SHORT));

        let data = command.data.unwrap();

        assert_eq!(data[0], GENERAL_AUTHENTICATE_TAG | (Asn1Class::Application | Asn1Form::Constructed));
        assert_eq!(data[1], 6);
        assert_eq!(data[2], u8::from(Asn1Class::ContextSpecific) | 1);
        assert_eq!(data[3], test_data.len() as u8);
        assert_eq!(&data[4..8], &test_data);
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
    fn test_command_apdu_generation() {
        let command = HealthCardCommand::general_authenticate(false).unwrap();
        let apdu_result =
            CardCommandApdu::new(command.cla, command.ins, command.p1, command.p2, command.data.clone(), command.ne);

        assert!(apdu_result.is_ok());

        let apdu = apdu_result.unwrap();

        assert_eq!(apdu.cla(), command.cla);
        assert_eq!(apdu.ins(), command.ins);
        assert_eq!(apdu.p1(), command.p1);
        assert_eq!(apdu.p2(), command.p2);
        assert_eq!(apdu.data_ref().unwrap(), &command.data.as_ref().unwrap()[..]);
        assert_eq!(apdu.expected_length(), command.ne);
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
}
