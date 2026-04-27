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

use crate::card::{
    parse_health_card_version2 as parse_core_health_card_version2,
    parse_list_public_keys as parse_core_list_public_keys, HealthCardVersion2 as CoreHealthCardVersion2,
    HealthCardVersion2Error, ListPublicKeyEntry as CoreListPublicKeyEntry, ListPublicKeyError,
    ListPublicKeys as CoreListPublicKeys,
};
use std::sync::Arc;
use thiserror::Error;

/// UniFFI error type for parsing typed card response data.
#[derive(Debug, Clone, Error)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum CardDataError {
    #[error("invalid argument: {reason}")]
    InvalidArgument { reason: String },
    #[error("decode error: {reason}")]
    Decode { reason: String },
}

impl From<HealthCardVersion2Error> for CardDataError {
    fn from(err: HealthCardVersion2Error) -> Self {
        Self::Decode { reason: err.to_string() }
    }
}

impl From<ListPublicKeyError> for CardDataError {
    fn from(err: ListPublicKeyError) -> Self {
        Self::Decode { reason: err.to_string() }
    }
}

/// Parsed content of `EF.Version2`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct HealthCardVersion2 {
    inner: CoreHealthCardVersion2,
}

impl From<CoreHealthCardVersion2> for HealthCardVersion2 {
    fn from(inner: CoreHealthCardVersion2) -> Self {
        Self { inner }
    }
}

#[uniffi::export]
impl HealthCardVersion2 {
    pub fn is_health_card_version_21(&self) -> bool {
        self.inner.is_health_card_version_21()
    }

    pub fn filling_instructions_version(&self) -> Vec<u8> {
        self.inner.filling_instructions_version().to_vec()
    }

    pub fn object_system_version(&self) -> Vec<u8> {
        self.inner.object_system_version().to_vec()
    }

    pub fn product_identification_object_system_version(&self) -> Vec<u8> {
        self.inner.product_identification_object_system_version().to_vec()
    }

    pub fn filling_instructions_environment_settings_version(&self) -> Vec<u8> {
        self.inner.fi_ef_environment_settings_version().to_vec()
    }

    pub fn filling_instructions_gdo_version(&self) -> Vec<u8> {
        self.inner.fi_ef_gdo_version().to_vec()
    }

    pub fn filling_instructions_atr_version(&self) -> Vec<u8> {
        self.inner.fi_ef_atr_version().to_vec()
    }

    pub fn filling_instructions_key_info_version(&self) -> Vec<u8> {
        self.inner.fi_ef_key_info_version().to_vec()
    }

    pub fn filling_instructions_logging_version(&self) -> Vec<u8> {
        self.inner.fi_ef_logging_version().to_vec()
    }
}

/// One parsed LIST PUBLIC KEY entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct ListPublicKeyEntry {
    inner: CoreListPublicKeyEntry,
}

impl From<CoreListPublicKeyEntry> for ListPublicKeyEntry {
    fn from(inner: CoreListPublicKeyEntry) -> Self {
        Self { inner }
    }
}

#[uniffi::export]
impl ListPublicKeyEntry {
    pub fn application_identifier(&self) -> Vec<u8> {
        self.inner.application_identifier().to_vec()
    }

    pub fn key_reference(&self) -> Vec<u8> {
        self.inner.key_reference().to_vec()
    }
}

/// Parsed LIST PUBLIC KEY response.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct ListPublicKeys {
    inner: CoreListPublicKeys,
}

impl From<CoreListPublicKeys> for ListPublicKeys {
    fn from(inner: CoreListPublicKeys) -> Self {
        Self { inner }
    }
}

#[uniffi::export]
impl ListPublicKeys {
    pub fn entries(&self) -> Vec<Arc<ListPublicKeyEntry>> {
        self.inner.entries().iter().cloned().map(ListPublicKeyEntry::from).map(Arc::new).collect()
    }

    pub fn key_references_for_application_identifier(&self, application_identifier: Vec<u8>) -> Vec<Vec<u8>> {
        self.inner.key_references_for_application_identifier(&application_identifier)
    }
}

/// Parses raw `EF.Version2` bytes into a typed representation.
#[uniffi::export]
pub fn parse_health_card_version2(data: Vec<u8>) -> Result<Arc<HealthCardVersion2>, CardDataError> {
    if data.is_empty() {
        return Err(CardDataError::InvalidArgument { reason: "data must not be empty".into() });
    }

    let version = parse_core_health_card_version2(&data)?;
    Ok(Arc::new(version.into()))
}

/// Parses raw LIST PUBLIC KEY response data into typed entries.
#[uniffi::export]
pub fn parse_list_public_keys(data: Vec<u8>) -> Result<Arc<ListPublicKeys>, CardDataError> {
    if data.is_empty() {
        return Err(CardDataError::InvalidArgument { reason: "data must not be empty".into() });
    }

    let entries = parse_core_list_public_keys(&data)?;
    Ok(Arc::new(entries.into()))
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
    fn parse_health_card_version2_exposes_versions() {
        let bytes = hex_to_bytes(
            "EF 2B C0 03 02 00 00 C1 03 04 04 00 C2 10 45 47 4B 47 32 20 20 20 20 20 20 20 20 01 03 04 C4 03 01 00 00 C5 03 02 00 00 C7 03 01 00 00",
        );

        let version = parse_health_card_version2(bytes).expect("version parsed");

        assert_eq!(version.filling_instructions_version(), vec![0x02, 0x00, 0x00]);
        assert_eq!(version.object_system_version(), vec![0x04, 0x04, 0x00]);
        assert!(version.is_health_card_version_21());
    }

    #[test]
    fn parse_list_public_keys_exposes_entries() {
        let bytes = hex_to_bytes(
            "E0 15 4F 07 D2 76 00 01 44 80 00 B6 0A 83 08 44 45 47 58 58 87 02 22 \
             E0 15 4F 07 D2 76 00 01 44 80 00 B6 0A 83 08 44 45 47 58 58 12 02 23",
        );

        let parsed = parse_list_public_keys(bytes).expect("entries parsed");

        assert_eq!(parsed.entries().len(), 2);
        assert_eq!(
            parsed.key_references_for_application_identifier(vec![0xD2, 0x76, 0x00, 0x01, 0x44, 0x80, 0x00]),
            vec![
                vec![0x44, 0x45, 0x47, 0x58, 0x58, 0x87, 0x02, 0x22],
                vec![0x44, 0x45, 0x47, 0x58, 0x58, 0x12, 0x02, 0x23]
            ]
        );
    }
}
