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

use std::convert::TryFrom;
use std::fmt;
use std::num::ParseIntError;

/// Minimum valid value for ShortFileIdentifier
const MIN_VALUE: u8 = 1;

/// Maximum valid value for ShortFileIdentifier
const MAX_VALUE: u8 = 30;

/// It is possible that the attribute type shortFileIdentifier is used by the file object types.
/// Short file identifiers are used for implicit file selection in the immediate context of a command.
/// The value of shortFileIdentifier MUST be an integer in the interval [1, 30]
///
/// ISO/IEC7816-4 and gemSpec_COS_3.14.0
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ShortFileIdentifier {
    /// The Short File Identifier value
    pub sf_id: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShortFileIdentifierError {
    /// The value is outside the valid range
    OutOfRange(u8),
    /// The hex string could not be parsed
    ParseError(ParseIntError),
    /// The hex string has an invalid length
    InvalidLength(usize),
}

impl fmt::Display for ShortFileIdentifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutOfRange(val) => write!(
                f,
                "Short File Identifier out of valid range [{},{}]: {}",
                MIN_VALUE, MAX_VALUE, val
            ),
            Self::ParseError(e) => write!(f, "Failed to parse hex string: {}", e),
            Self::InvalidLength(len) => write!(
                f,
                "Invalid hex string length: {}. Expected 2 characters.",
                len
            ),
        }
    }
}

impl std::error::Error for ShortFileIdentifierError {}

impl ShortFileIdentifier {
    /// Creates a new ShortFileIdentifier.
    ///
    /// # Arguments
    /// * `sf_id` - The Short File Identifier value
    pub fn new(sf_id: u8) -> Result<Self, ShortFileIdentifierError> {
        if sf_id < MIN_VALUE || sf_id > MAX_VALUE {
            Err(ShortFileIdentifierError::OutOfRange(sf_id))
        } else {
            Ok(ShortFileIdentifier { sf_id })
        }
    }

    /// Creates a new ShortFileIdentifier from a hex string.
    ///
    /// # Arguments
    /// * `hex_sf_id` - The hex string representing the Short File Identifier
    pub fn from_hex(hex_sf_id: &str) -> Result<Self, ShortFileIdentifierError> {
        if hex_sf_id.len() != 2 {
            return Err(ShortFileIdentifierError::InvalidLength(hex_sf_id.len()));
        }

        let value =
            u8::from_str_radix(hex_sf_id, 16).map_err(ShortFileIdentifierError::ParseError)?;

        Self::new(value)
    }
}

impl TryFrom<u8> for ShortFileIdentifier {
    type Error = ShortFileIdentifierError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        ShortFileIdentifier::new(value)
    }
}

impl TryFrom<&str> for ShortFileIdentifier {
    type Error = ShortFileIdentifierError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        ShortFileIdentifier::from_hex(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_sfi() {
        let sfi = ShortFileIdentifier::new(1).unwrap();
        assert_eq!(sfi.sf_id, 1);

        let sfi = ShortFileIdentifier::new(15).unwrap();
        assert_eq!(sfi.sf_id, 15);

        let sfi = ShortFileIdentifier::new(30).unwrap();
        assert_eq!(sfi.sf_id, 30);
    }

    #[test]
    fn test_invalid_sfi() {
        assert!(ShortFileIdentifier::new(0).is_err());
        assert!(ShortFileIdentifier::new(31).is_err());
    }

    #[test]
    fn test_from_hex() {
        let sfi = ShortFileIdentifier::from_hex("01").unwrap();
        assert_eq!(sfi.sf_id, 1);

        let sfi = ShortFileIdentifier::from_hex("1E").unwrap();
        assert_eq!(sfi.sf_id, 30);
    }

    #[test]
    fn test_invalid_hex() {
        assert!(ShortFileIdentifier::from_hex("00").is_err());
        assert!(ShortFileIdentifier::from_hex("1F").is_err());
        assert!(ShortFileIdentifier::from_hex("G1").is_err());
        assert!(ShortFileIdentifier::from_hex("").is_err());
        assert!(ShortFileIdentifier::from_hex("123").is_err());
    }

    #[test]
    fn test_try_from() {
        let sfi: ShortFileIdentifier = 5.try_into().unwrap();
        assert_eq!(sfi.sf_id, 5);

        let sfi: ShortFileIdentifier = "0A".try_into().unwrap();
        assert_eq!(sfi.sf_id, 10);
    }
}
