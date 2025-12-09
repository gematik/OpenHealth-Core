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

/// A file identifier may reference any file. It consists of two bytes. The value '3F00'
/// is reserved for referencing the MF. The value 'FFFF' is reserved for future use.
/// The value '3FFF' is reserved. The value '0000' is reserved.
/// In order to unambiguously select any file by its identifier, all EFs and DFs
/// immediately under a given DF shall have different file identifiers.
///
/// ISO/IEC 7816-4 and gemSpec_COS_3.14.0
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileIdentifier {
    /// The File Identifier value
    fid: u16,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum FileIdentifierError {
    /// The File Identifier length is invalid
    #[error("Requested length of byte array for a File Identifier value is 2 but was {0}")]
    InvalidLength(usize),

    /// The File Identifier is out of range
    #[error("File Identifier is out of range: 0x{0:04X}")]
    OutOfRange(u16),
}

impl FileIdentifier {
    /// Creates a new FileIdentifier.
    ///
    /// # Arguments
    /// * `fid` - The File Identifier as a u16
    ///
    /// # Returns
    /// * `Result<Self, FileIdentifierError>` - The new FileIdentifier or an error
    pub fn new(fid: u16) -> Result<Self, FileIdentifierError> {
        // Check if FID is in valid range according to gemSpec_COS_3.14.0#N006.700, N006.900
        if (!(0x1000..=0xFEFF).contains(&fid) && fid != 0x011C) || fid == 0x3FFF {
            return Err(FileIdentifierError::OutOfRange(fid));
        }

        Ok(Self { fid })
    }

    pub fn get_fid(&self) -> Vec<u8> {
        vec![(self.fid >> 8) as u8, (self.fid & 0xFF) as u8]
    }

    /// Consumes the identifier and returns the raw bytes.
    pub fn into_bytes(self) -> [u8; 2] {
        self.to_bytes()
    }

    /// Creates a new FileIdentifier from a byte array.
    ///
    /// # Arguments
    /// * `bytes` - The File Identifier as a byte array (must be 2 bytes)
    ///
    /// # Returns
    /// * `Result<Self, FileIdentifierError>` - The new FileIdentifier or an error
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, FileIdentifierError> {
        if bytes.len() != 2 {
            return Err(FileIdentifierError::InvalidLength(bytes.len()));
        }

        let fid = ((bytes[0] as u16) << 8) | (bytes[1] as u16);
        Self::new(fid)
    }

    /// Returns the file identifier as a byte array.
    pub fn to_bytes(&self) -> [u8; 2] {
        [(self.fid >> 8) as u8, self.fid as u8]
    }

    /// Returns the file identifier as a u16.
    pub fn value(&self) -> u16 {
        self.fid
    }
}

impl TryFrom<u16> for FileIdentifier {
    type Error = FileIdentifierError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl TryFrom<&[u8]> for FileIdentifier {
    type Error = FileIdentifierError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::from_bytes(value)
    }
}

impl fmt::Display for FileIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:04X}", self.fid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_fid() {
        // Valid FID
        let fid = 0x1234;
        let file_id = FileIdentifier::new(fid).unwrap();
        assert_eq!(file_id.value(), fid);

        // Special case 0x011C (which is allowed despite being < 0x1000)
        let fid = 0x011C;
        let file_id = FileIdentifier::new(fid).unwrap();
        assert_eq!(file_id.value(), fid);
    }

    #[test]
    fn test_invalid_fid() {
        // Too small
        let fid = 0x0FFF;
        let result = FileIdentifier::new(fid);
        assert!(result.is_err());

        // Too large
        let fid = 0xFF00;
        let result = FileIdentifier::new(fid);
        assert!(result.is_err());

        // Reserved value
        let fid = 0x3FFF;
        let result = FileIdentifier::new(fid);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_bytes() {
        // Valid bytes
        let bytes = [0x12, 0x34];
        let file_id = FileIdentifier::from_bytes(&bytes).unwrap();
        assert_eq!(file_id.value(), 0x1234);

        // Invalid length
        let bytes = [0x12, 0x34, 0x56];
        let result = FileIdentifier::from_bytes(&bytes);
        assert!(result.is_err());

        if let Err(FileIdentifierError::InvalidLength(len)) = result {
            assert_eq!(len, 3);
        } else {
            panic!("Expected InvalidLength error");
        }
    }

    #[test]
    fn test_to_bytes() {
        let fid = 0x1234;
        let file_id = FileIdentifier::new(fid).unwrap();
        assert_eq!(file_id.to_bytes(), [0x12, 0x34]);
        assert_eq!(file_id.into_bytes(), [0x12, 0x34]);
    }

    #[test]
    fn test_try_from() {
        // From u16
        let fid: u16 = 0x1234;
        let file_id: FileIdentifier = fid.try_into().unwrap();
        assert_eq!(file_id.value(), fid);

        // From bytes
        let bytes = [0x12, 0x34];
        let file_id: FileIdentifier = bytes.as_ref().try_into().unwrap();
        assert_eq!(file_id.value(), 0x1234);
    }

    #[test]
    fn test_display() {
        let fid = 0x1234;
        let file_id = FileIdentifier::new(fid).unwrap();
        assert_eq!(format!("{}", file_id), "1234");
    }
}
