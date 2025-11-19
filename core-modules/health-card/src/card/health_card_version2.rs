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

use crate::asn1::decoder::Asn1Decoder;
use asn1::error::Asn1DecoderError;
use asn1::tag::Asn1Id;
use std::collections::HashMap;
use thiserror::Error;

/// Tags used within EF.Version2 (gemSpec_COS 14.2.3)
const TAG_WRAPPER: Asn1Id = Asn1Id::prv(0x0F).constructed();
const TAG_FILLING_INSTRUCTIONS_VERSION: u8 = 0xC0;
const TAG_OBJECT_SYSTEM_VERSION: u8 = 0xC1;
const TAG_PRODUCT_IDENTIFICATION_OS_VERSION: u8 = 0xC2;
const TAG_FILLING_INSTRUCTIONS_EF_ENVIRONMENT_SETTINGS_VERSION: u8 = 0xC3;
const TAG_FILLING_INSTRUCTIONS_EF_GDO_VERSION: u8 = 0xC4;
const TAG_FILLING_INSTRUCTIONS_EF_ATR_VERSION: u8 = 0xC5;
const TAG_FILLING_INSTRUCTIONS_EF_KEY_INFO_VERSION: u8 = 0xC6;
const TAG_FILLING_INSTRUCTIONS_EF_LOGGING_VERSION: u8 = 0xC7;
const MIN_OBJECT_SYSTEM_VERSION_FOR_EGK21: u32 = (4u32 << 16) | (4u32 << 8);

/// Errors that can occur while parsing EF.Version2 content.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HealthCardVersion2Error {
    /// TLV structure is malformed (e.g. truncated length field).
    #[error("malformed EF.Version2 TLV structure")]
    MalformedTlv,
    /// The TLV wrapper claims to be longer than the provided data.
    #[error("EF.Version2 length does not match payload")]
    LengthMismatch,
    /// A mandatory tag is missing.
    #[error("mandatory tag 0x{0:02X} missing")]
    MissingTag(u8),
}

/// Parsed content of EF.Version2 holding the version matrix of the card operating system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthCardVersion2 {
    fi_version: Vec<u8>,
    object_system_version: Vec<u8>,
    product_identification_object_system_version: Vec<u8>,
    fi_ef_environment_settings_version: Vec<u8>,
    fi_ef_gdo_version: Vec<u8>,
    fi_ef_atr_version: Vec<u8>,
    fi_ef_key_info_version: Vec<u8>,
    fi_ef_logging_version: Vec<u8>,
}

impl HealthCardVersion2 {
    /// Returns true if the version matrix indicates an eGK version 2.1 card.
    pub fn is_health_card_version_21(&self) -> bool {
        if self.object_system_version.len() < 2 {
            return false;
        }

        let major = u32::from(self.object_system_version[0]);
        let minor = u32::from(self.object_system_version[1]);
        let version = (major << 16) | (minor << 8) | minor;

        version >= MIN_OBJECT_SYSTEM_VERSION_FOR_EGK21
    }
}

/// Parses the binary content of EF.Version2 into a [HealthCardVersion2] structure.
pub fn parse_health_card_version2(data: &[u8]) -> Result<HealthCardVersion2, HealthCardVersion2Error> {
    if data.is_empty() {
        return Err(HealthCardVersion2Error::MalformedTlv);
    }

    let decoder = Asn1Decoder::new(data);
    decoder.read(|reader| {
        reader.advance_with_tag(TAG_WRAPPER, |reader| {
            let mut entries: HashMap<u8, Vec<u8>> = HashMap::new();

            while reader.remaining_length() > 0 {
                let tag = reader.read_tag()?;
                if tag.number >= 0x1F {
                    return Err(Asn1DecoderError::custom("high-tag-number form not supported for EF.Version2").into());
                }

                let length = reader.read_length()?;
                if length < 0 {
                    return Err(Asn1DecoderError::custom("indefinite lengths are not supported in EF.Version2").into());
                }

                let value = reader.read_bytes(length as usize)?;
                let tag_byte = u8::from(tag.class) | u8::from(tag.form) | (tag.number as u8);
                entries.insert(tag_byte, value);
            }

            let mut take_or_err = |tag: u8| -> Result<Vec<u8>, HealthCardVersion2Error> {
                entries.remove(&tag).ok_or(HealthCardVersion2Error::MissingTag(tag))
            };

            let fi_version = take_or_err(TAG_FILLING_INSTRUCTIONS_VERSION)?;
            let object_system_version = take_or_err(TAG_OBJECT_SYSTEM_VERSION)?;
            let product_identification_object_system_version =
                take_or_err(TAG_PRODUCT_IDENTIFICATION_OS_VERSION)?;

            let mut optional = |tag: u8| entries.remove(&tag).unwrap_or_default();

            Ok(HealthCardVersion2 {
                fi_version,
                object_system_version,
                product_identification_object_system_version,
                fi_ef_environment_settings_version: optional(TAG_FILLING_INSTRUCTIONS_EF_ENVIRONMENT_SETTINGS_VERSION),
                fi_ef_gdo_version: optional(TAG_FILLING_INSTRUCTIONS_EF_GDO_VERSION),
                fi_ef_atr_version: optional(TAG_FILLING_INSTRUCTIONS_EF_ATR_VERSION),
                fi_ef_key_info_version: optional(TAG_FILLING_INSTRUCTIONS_EF_KEY_INFO_VERSION),
                fi_ef_logging_version: optional(TAG_FILLING_INSTRUCTIONS_EF_LOGGING_VERSION),
            })
        })
    })
}

impl From<Asn1DecoderError> for HealthCardVersion2Error {
    fn from(_: Asn1DecoderError) -> Self {
        HealthCardVersion2Error::MalformedTlv
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_to_bytes(input: &str) -> Vec<u8> {
        input
            .split_whitespace()
            .filter(|chunk| !chunk.is_empty())
            .map(|chunk| u8::from_str_radix(chunk, 16).unwrap())
            .collect()
    }

    fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn parse_health_card_version_success() {
        let payload = "EF 2B C0 03 02 00 00 C1 03 04 04 00 C2 10 45 47 4B 47 32 20 20 20 20 20 20 20 ".to_owned()
            + "20 01 03 04 C4 03 01 00 00 C5 03 02 00 00 C7 03 01 00 00";
        let bytes = hex_to_bytes(&payload);

        let version = parse_health_card_version2(&bytes).expect("version parsed");

        assert_eq!(bytes_to_hex(&version.fi_ef_atr_version), "02 00 00");
        assert_eq!(bytes_to_hex(&version.fi_ef_environment_settings_version), "");
        assert_eq!(bytes_to_hex(&version.fi_ef_gdo_version), "01 00 00");
        assert_eq!(bytes_to_hex(&version.fi_ef_key_info_version), "");
        assert_eq!(bytes_to_hex(&version.fi_ef_logging_version), "01 00 00");
        assert!(version.is_health_card_version_21());
    }

    #[test]
    fn parse_health_card_version_missing_tag() {
        let bytes = hex_to_bytes("EF 05 C1 03 04 03 02");
        let err = parse_health_card_version2(&bytes).unwrap_err();
        assert!(matches!(err, HealthCardVersion2Error::MissingTag(TAG_FILLING_INSTRUCTIONS_VERSION)));
    }
}
