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

use openhealth_asn1::decoder::{Asn1Decoder, Asn1Length, ParserScope};
use openhealth_asn1::error::Asn1DecoderError;
use openhealth_asn1::tag::{Asn1Class, Asn1Form, Asn1Id};
use thiserror::Error;

const TAG_LIST_PUBLIC_KEY_ENTRY: Asn1Id = Asn1Id::new(Asn1Class::Private, Asn1Form::Constructed, 0x00);
const TAG_APPLICATION_IDENTIFIER: Asn1Id = Asn1Id::app(0x0F).primitive();
const TAG_KEY_REFERENCE: Asn1Id = Asn1Id::ctx(0x03).primitive();

/// Errors that can occur while parsing LIST PUBLIC KEY response data.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ListPublicKeyError {
    #[error("malformed LIST PUBLIC KEY TLV structure")]
    MalformedTlv,
    #[error("LIST PUBLIC KEY response does not contain any entries")]
    EmptyResponse,
    #[error("LIST PUBLIC KEY entry missing application identifier")]
    MissingApplicationIdentifier,
    #[error("LIST PUBLIC KEY entry missing key reference")]
    MissingKeyReference,
}

/// One parsed LIST PUBLIC KEY entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPublicKeyEntry {
    application_identifier: Vec<u8>,
    key_reference: Vec<u8>,
}

impl ListPublicKeyEntry {
    pub fn application_identifier(&self) -> &[u8] {
        &self.application_identifier
    }

    pub fn key_reference(&self) -> &[u8] {
        &self.key_reference
    }
}

/// Parsed LIST PUBLIC KEY response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListPublicKeys {
    entries: Vec<ListPublicKeyEntry>,
}

impl ListPublicKeys {
    pub fn entries(&self) -> &[ListPublicKeyEntry] {
        &self.entries
    }

    pub fn key_references_for_application_identifier(&self, application_identifier: &[u8]) -> Vec<Vec<u8>> {
        self.entries
            .iter()
            .filter(|entry| entry.application_identifier() == application_identifier)
            .map(|entry| entry.key_reference().to_vec())
            .collect()
    }
}

/// Parses the data field of a successful LIST PUBLIC KEY response.
pub fn parse_list_public_keys(data: &[u8]) -> Result<ListPublicKeys, ListPublicKeyError> {
    if data.is_empty() {
        return Err(ListPublicKeyError::EmptyResponse);
    }

    let entries = Asn1Decoder::new(data).read::<_, ListPublicKeyError>(|scope| {
        let mut entries = Vec::new();
        while scope.remaining_length() > 0 {
            let tag = scope.read_tag()?;
            if tag != TAG_LIST_PUBLIC_KEY_ENTRY {
                return Err(ListPublicKeyError::MalformedTlv);
            }
            let entry_data = read_definite_value(scope, "LIST PUBLIC KEY top-level entry")?;
            entries.push(parse_entry(&entry_data)?);
        }
        Ok::<Vec<ListPublicKeyEntry>, ListPublicKeyError>(entries)
    })?;

    if entries.is_empty() {
        return Err(ListPublicKeyError::EmptyResponse);
    }

    Ok(ListPublicKeys { entries })
}

fn parse_entry(data: &[u8]) -> Result<ListPublicKeyEntry, ListPublicKeyError> {
    let mut application_identifier = None;
    let mut key_reference = None;

    Asn1Decoder::new(data).read::<_, ListPublicKeyError>(|scope| {
        while scope.remaining_length() > 0 {
            let tag = scope.read_tag()?;
            let value = read_definite_value(scope, "LIST PUBLIC KEY entry")?;
            if tag == TAG_APPLICATION_IDENTIFIER {
                application_identifier = Some(value);
                continue;
            }

            if tag.form == Asn1Form::Constructed && key_reference.is_none() {
                key_reference = extract_key_reference(&value)?;
            }
        }
        Ok::<(), ListPublicKeyError>(())
    })?;

    Ok(ListPublicKeyEntry {
        application_identifier: application_identifier.ok_or(ListPublicKeyError::MissingApplicationIdentifier)?,
        key_reference: key_reference.ok_or(ListPublicKeyError::MissingKeyReference)?,
    })
}

fn extract_key_reference(data: &[u8]) -> Result<Option<Vec<u8>>, ListPublicKeyError> {
    Asn1Decoder::new(data).read::<_, ListPublicKeyError>(|scope| {
        while scope.remaining_length() > 0 {
            let tag = scope.read_tag()?;
            let value = read_definite_value(scope, "LIST PUBLIC KEY key container")?;
            if tag == TAG_KEY_REFERENCE {
                return Ok::<Option<Vec<u8>>, ListPublicKeyError>(Some(value));
            }
        }
        Ok::<Option<Vec<u8>>, ListPublicKeyError>(None)
    })
}

fn read_definite_value(scope: &mut ParserScope<'_>, context: &str) -> Result<Vec<u8>, ListPublicKeyError> {
    match scope.read_length()? {
        Asn1Length::Definite(length) => scope.read_bytes(length).map_err(Into::into),
        Asn1Length::Indefinite => {
            Err(Asn1DecoderError::custom(format!("indefinite lengths are not supported in {context}")).into())
        }
    }
}

impl From<Asn1DecoderError> for ListPublicKeyError {
    fn from(_: Asn1DecoderError) -> Self {
        ListPublicKeyError::MalformedTlv
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

    #[test]
    fn parse_virtual_card_list_public_key_response() {
        let bytes = hex_to_bytes(
            "E0 15 4F 07 D2 76 00 01 44 80 00 B6 0A 83 08 44 45 47 58 58 87 02 22 \
             E0 15 4F 07 D2 76 00 01 44 80 00 B6 0A 83 08 44 45 47 58 58 12 02 23 \
             E0 19 4F 07 D2 76 00 01 44 80 00 A4 0E 83 0C 00 0A 80 27 60 01 01 16 99 90 21 01 \
             E0 19 4F 07 D2 76 00 01 44 80 00 A4 0E 83 0C 4D 6F 72 70 68 6F 41 43 43 45 53 53 \
             E0 16 4F 07 D2 76 00 01 44 80 00 B6 0B 83 09 4D 6F 72 70 68 6F 56 45 52 \
             E0 15 4F 07 D2 76 00 01 44 80 00 B6 0A 83 08 44 45 47 58 58 86 02 20 \
             E0 15 4F 07 D2 76 00 01 44 80 00 B6 0A 83 08 00 00 00 00 00 00 00 13",
        );

        let response = parse_list_public_keys(&bytes).expect("list parsed");

        assert_eq!(response.entries().len(), 7);
        assert_eq!(response.entries()[0].application_identifier(), &[0xD2, 0x76, 0x00, 0x01, 0x44, 0x80, 0x00]);
        assert_eq!(response.entries()[0].key_reference(), &[0x44, 0x45, 0x47, 0x58, 0x58, 0x87, 0x02, 0x22]);
        assert_eq!(
            response.key_references_for_application_identifier(&[0xD2, 0x76, 0x00, 0x01, 0x44, 0x80, 0x00]).len(),
            7
        );
    }

    #[test]
    fn parse_list_public_key_rejects_empty_data() {
        let err = parse_list_public_keys(&[]).unwrap_err();
        assert!(matches!(err, ListPublicKeyError::EmptyResponse));
    }

    #[test]
    fn parse_list_public_key_requires_application_identifier() {
        let bytes = hex_to_bytes("E0 05 83 03 01 02 03");
        let err = parse_list_public_keys(&bytes).unwrap_err();
        assert!(matches!(err, ListPublicKeyError::MissingApplicationIdentifier));
    }

    #[test]
    fn parse_list_public_key_requires_key_reference() {
        let bytes = hex_to_bytes("E0 09 4F 07 D2 76 00 01 44 80 00");
        let err = parse_list_public_keys(&bytes).unwrap_err();
        assert!(matches!(err, ListPublicKeyError::MissingKeyReference));
    }

    #[test]
    fn parse_list_public_key_finds_key_reference_after_other_nested_tlv() {
        let bytes = hex_to_bytes("E0 11 4F 07 D2 76 00 01 44 80 00 B6 06 80 01 AA 83 01 23");

        let parsed = parse_list_public_keys(&bytes).expect("entry parsed");

        assert_eq!(parsed.entries().len(), 1);
        assert_eq!(parsed.entries()[0].key_reference(), &[0x23]);
    }

    #[test]
    fn parse_list_public_key_requires_key_reference_inside_constructed_container() {
        let bytes = hex_to_bytes("E0 0E 4F 07 D2 76 00 01 44 80 00 B6 03 80 01 AA");

        let err = parse_list_public_keys(&bytes).unwrap_err();

        assert!(matches!(err, ListPublicKeyError::MissingKeyReference));
    }
}
