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

use std::fmt;
use thiserror::Error;

/// Minimum valid length for ApplicationIdentifier
const AID_MIN_LENGTH: usize = 5;

/// Maximum valid length for ApplicationIdentifier
const AID_MAX_LENGTH: usize = 16;

/// An application identifier (AID) is used to address an application on the healthcard
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationIdentifier {
    /// The Application Identifier value
    aid: Vec<u8>,
}

#[derive(Debug, Error, Clone, PartialEq)]
pub enum ApplicationIdentifierError {
    /// The AID length is outside the valid range
    #[error("Application File Identifier length out of valid range [{AID_MIN_LENGTH},{AID_MAX_LENGTH}]: {0}")]
    InvalidLength(usize),

    /// Error parsing hex string
    #[error("Failed to parse hex string: {0}")]
    ParseError(#[from] hex::FromHexError),
}

impl ApplicationIdentifier {
    /// Creates a new ApplicationIdentifier.
    ///
    /// # Arguments
    /// * `aid` - The Application Identifier as a byte array
    ///
    /// # Returns
    /// * `Result<Self, ApplicationIdentifierError>` - The new ApplicationIdentifier or an error
    pub fn new(aid: Vec<u8>) -> Result<Self, ApplicationIdentifierError> {
        if aid.len() < AID_MIN_LENGTH || aid.len() > AID_MAX_LENGTH {
            return Err(ApplicationIdentifierError::InvalidLength(aid.len()));
        }

        Ok(Self { aid })
    }

    /// Creates a new ApplicationIdentifier from a hex string.
    ///
    /// # Arguments
    /// * `hex_aid` - The Application Identifier as a hex string
    ///
    /// # Returns
    /// * `Result<Self, ApplicationIdentifierError>` - The new ApplicationIdentifier or an error
    pub fn from_hex(hex_aid: &str) -> Result<Self, ApplicationIdentifierError> {
        let aid = hex::decode(hex_aid)?;
        Self::new(aid)
    }

    /// Returns the AID bytes.
    pub fn aid(&self) -> &[u8] {
        &self.aid
    }

    /// Returns the AID bytes (alias for `aid` to align with other identifiers).
    pub fn as_bytes(&self) -> &[u8] {
        &self.aid
    }

    /// Consumes the identifier and returns owned bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.aid
    }

    /// Returns a mutable reference to the AID bytes.
    pub fn aid_mut(&mut self) -> &mut Vec<u8> {
        &mut self.aid
    }
}

impl TryFrom<&str> for ApplicationIdentifier {
    type Error = ApplicationIdentifierError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_hex(value)
    }
}

impl TryFrom<Vec<u8>> for ApplicationIdentifier {
    type Error = ApplicationIdentifierError;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl fmt::Display for ApplicationIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.aid))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_aid() {
        // Valid AID with minimum length
        let aid = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let app_id = ApplicationIdentifier::new(aid.clone()).unwrap();
        assert_eq!(app_id.aid(), aid.as_slice());

        // Valid AID with maximum length
        let aid = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        let app_id = ApplicationIdentifier::new(aid.clone()).unwrap();
        assert_eq!(app_id.aid(), aid.as_slice());
    }

    #[test]
    fn test_invalid_aid_length() {
        // Too short
        let aid = vec![0x01, 0x02, 0x03, 0x04];
        let result = ApplicationIdentifier::new(aid);
        assert!(result.is_err());

        if let Err(ApplicationIdentifierError::InvalidLength(len)) = result {
            assert_eq!(len, 4);
        } else {
            panic!("Expected InvalidLength error");
        }

        // Too long
        let aid =
            vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11];
        let result = ApplicationIdentifier::new(aid);
        assert!(result.is_err());

        if let Err(ApplicationIdentifierError::InvalidLength(len)) = result {
            assert_eq!(len, 17);
        } else {
            panic!("Expected InvalidLength error");
        }
    }

    #[test]
    fn test_from_hex() {
        let hex_aid = "0102030405";
        let app_id = ApplicationIdentifier::from_hex(hex_aid).unwrap();
        assert_eq!(app_id.aid(), vec![0x01, 0x02, 0x03, 0x04, 0x05].as_slice());

        // Invalid hex string
        let hex_aid = "0102030Z05";
        let result = ApplicationIdentifier::from_hex(hex_aid);
        assert!(result.is_err());

        // Valid hex but invalid length
        let hex_aid = "01020304";
        let result = ApplicationIdentifier::from_hex(hex_aid);
        assert!(result.is_err());
    }

    #[test]
    fn test_try_from() {
        // From string
        let hex_aid = "0102030405";
        let app_id: ApplicationIdentifier = hex_aid.try_into().unwrap();
        assert_eq!(app_id.aid(), vec![0x01, 0x02, 0x03, 0x04, 0x05].as_slice());

        // From Vec<u8>
        let bytes = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let app_id: ApplicationIdentifier = bytes.try_into().unwrap();
        assert_eq!(app_id.aid(), vec![0x01, 0x02, 0x03, 0x04, 0x05].as_slice());
    }

    #[test]
    fn test_display() {
        let aid = vec![0x01, 0x02, 0x03, 0x04, 0x05];
        let app_id = ApplicationIdentifier::new(aid).unwrap();
        assert_eq!(format!("{}", app_id), "0102030405");
        assert_eq!(app_id.as_bytes(), &[0x01, 0x02, 0x03, 0x04, 0x05]);
        assert_eq!(app_id.clone().into_bytes(), vec![0x01, 0x02, 0x03, 0x04, 0x05]);
    }
}
