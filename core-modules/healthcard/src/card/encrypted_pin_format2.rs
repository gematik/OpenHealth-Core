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
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// The format 2 PIN block has been specified for use with IC cards. The format 2 PIN block shall only be used in
/// an offline environment and shall not be used for online PIN verification. This PIN block is constructed by
/// concatenation of two fields: the plain text PIN field and the filler field.
///
/// See "ISO 9564-1"
const NIBBLE_SIZE: u8 = 4;
const MIN_PIN_LEN: usize = 4; // specSpec_COS#N008.000
const MAX_PIN_LEN: usize = 12; // specSpec_COS#N008.000
const FORMAT_PIN_2_ID: u8 = 0x02 << NIBBLE_SIZE; // specSpec_COS#N008.100
const FORMAT2_PIN_SIZE: usize = 8;
const FORMAT2_PIN_FILLER: u8 = 0x0F;
const MIN_DIGIT: u8 = 0; // specSpec_COS#N008.000
const MAX_DIGIT: u8 = 9; // specSpec_COS#N008.000
const STRING_INT_OFFSET: u8 = 48;

/// Represents an encrypted PIN in format 2.
///
/// The format 2 PIN block is used with IC cards in an offline environment and is constructed by
/// concatenating the plain text PIN field and a filler field.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EncryptedPinFormat2 {
    bytes: Vec<u8>,
}

/// Errors that can occur while encoding a PIN into format 2.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum PinBlockError {
    /// A non-digit character was supplied.
    #[error("PIN digit value is out of range of a decimal digit: {0}")]
    NonDigit(char),
    /// The PIN was shorter than the minimum allowed length.
    #[error("PIN length is too short, min length is {min}, but was {length}")]
    TooShort { length: usize, min: usize },
    /// The PIN was longer than the maximum allowed length.
    #[error("PIN length is too long, max length is {max}, but was {length}")]
    TooLong { length: usize, max: usize },
    /// A provided encrypted block has an unexpected length.
    #[error("PIN block length is invalid, expected {expected} bytes but was {actual}")]
    InvalidBlockLength { expected: usize, actual: usize },
}

impl EncryptedPinFormat2 {
    /// Creates a new EncryptedPinFormat2 from a PIN string.
    ///
    /// # Arguments
    /// * `pin` - The PIN string to be encrypted. The PIN must be between 4 and 12 digits long.
    pub fn new(pin: &str) -> Result<Self, PinBlockError> {
        if pin.len() < MIN_PIN_LEN {
            return Err(PinBlockError::TooShort { length: pin.len(), min: MIN_PIN_LEN });
        }
        if pin.len() > MAX_PIN_LEN {
            return Err(PinBlockError::TooLong { length: pin.len(), max: MAX_PIN_LEN });
        }

        let mut int_pin = Vec::with_capacity(pin.len());
        for c in pin.chars() {
            let digit = c as u8 - STRING_INT_OFFSET;
            if !(MIN_DIGIT..=MAX_DIGIT).contains(&digit) {
                return Err(PinBlockError::NonDigit(c));
            }
            int_pin.push(digit);
        }

        let mut format2 = [0u8; FORMAT2_PIN_SIZE]; // specSpec_COS#N008.100
        format2[0] = FORMAT_PIN_2_ID + int_pin.len() as u8;

        for (i, &digit) in int_pin.iter().enumerate() {
            if (i + 2) % 2 == 0 {
                format2[1 + i / 2] += digit << NIBBLE_SIZE;
            } else {
                format2[1 + i / 2] += digit;
            }
        }

        for i in int_pin.len()..(2 * FORMAT2_PIN_SIZE - 2) {
            if i % 2 == 0 {
                format2[1 + i / 2] += FORMAT2_PIN_FILLER << NIBBLE_SIZE;
            } else {
                format2[1 + i / 2] += FORMAT2_PIN_FILLER;
            }
        }

        Ok(Self { bytes: format2.to_vec() })
    }

    /// Constructs an already-encrypted PIN block without validating contents.
    pub fn from_encrypted_bytes(bytes: Vec<u8>) -> Result<Self, PinBlockError> {
        if bytes.len() != FORMAT2_PIN_SIZE {
            return Err(PinBlockError::InvalidBlockLength { expected: FORMAT2_PIN_SIZE, actual: bytes.len() });
        }

        Ok(Self { bytes })
    }

    /// Returns a reference to the encrypted bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the struct and returns the owned bytes inside a zeroizing guard.
    pub fn into_zeroizing_bytes(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(std::mem::take(&mut self.bytes))
    }
}

impl fmt::Debug for EncryptedPinFormat2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedPinFormat2").field("len", &self.bytes.len()).finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypted_pin_format2_creation() {
        let pin = "1234";
        let encrypted = EncryptedPinFormat2::new(pin).unwrap();

        // First byte should be 0x24 (FORMAT_PIN_2_ID + pin length)
        assert_eq!(encrypted.as_bytes()[0], 0x24);
        assert_eq!(encrypted.as_bytes().len(), FORMAT2_PIN_SIZE);
    }

    #[test]
    fn test_encrypted_pin_format2_with_longer_pin() {
        let pin = "123456";
        let encrypted = EncryptedPinFormat2::new(pin).unwrap();

        assert_eq!(encrypted.as_bytes()[0], 0x26);
    }

    #[test]
    fn test_encrypted_pin_format2_too_short() {
        let err = EncryptedPinFormat2::new("123").unwrap_err();
        assert!(matches!(err, PinBlockError::TooShort { .. }));
    }

    #[test]
    fn test_encrypted_pin_format2_too_long() {
        let err = EncryptedPinFormat2::new("1234567890123").unwrap_err();
        assert!(matches!(err, PinBlockError::TooLong { .. }));
    }

    #[test]
    fn test_encrypted_pin_format2_invalid_digit() {
        let err = EncryptedPinFormat2::new("123a").unwrap_err();
        assert!(matches!(err, PinBlockError::NonDigit('a')));
    }

    #[test]
    fn test_specific_pin_value() {
        let pin = "1234";
        let encrypted = EncryptedPinFormat2::new(pin).unwrap();

        assert_eq!(encrypted.as_bytes()[0], 0x24);
        assert_eq!(encrypted.as_bytes()[1], 0x12);
        assert_eq!(encrypted.as_bytes()[2], 0x34);
        assert_eq!(encrypted.as_bytes()[3], 0xFF);
        assert_eq!(encrypted.as_bytes()[4], 0xFF);
        assert_eq!(encrypted.as_bytes()[5], 0xFF);
        assert_eq!(encrypted.as_bytes()[6], 0xFF);
        assert_eq!(encrypted.as_bytes()[7], 0xFF);
    }
}
