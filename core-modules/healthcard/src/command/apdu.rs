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

pub const EXPECTED_LENGTH_WILDCARD_EXTENDED: usize = 65536;

pub const EXPECTED_LENGTH_WILDCARD_SHORT: usize = 256;

#[derive(Debug, Error, Clone)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
pub enum ApduError {
    #[error("Invalid APDU header: {0}")]
    InvalidHeader(String),
    #[error("Invalid APDU length: {0}")]
    InvalidLength(String),
    #[error("Invalid APDU: {0}")]
    InvalidApdu(String),
}

/// Common trait for all APDU types
pub trait Apdu {
    fn bytes(&self) -> &[u8];
    fn to_bytes(&self) -> Vec<u8>;
}

/// Encodes the data length (Nc) for extended length APDUs (Lc1, Lc2).
///
/// # Arguments
/// * `nc` - The data length (number of data bytes).
fn encode_data_length_extended(nc: usize) -> Result<[u8; 3], ApduError> {
    if nc == 0 || nc > EXPECTED_LENGTH_WILDCARD_EXTENDED {
        return Err(ApduError::InvalidLength(format!(
            "APDU command data length must be in range [1, {EXPECTED_LENGTH_WILDCARD_EXTENDED}]"
        )));
    }
    Ok([0x0, ((nc >> 8) & 0xFF) as u8, (nc & 0xFF) as u8])
}

/// Encodes the data length (Nc) for short length APDUs (Lc).
///
/// # Arguments
/// * `nc` - The data length (number of data bytes).
fn encode_data_length_short(nc: usize) -> Result<[u8; 1], ApduError> {
    if nc == 0 || nc > EXPECTED_LENGTH_WILDCARD_SHORT {
        return Err(ApduError::InvalidLength("Data length (nc) must be in range [1, 255] for short APDUs".to_string()));
    }
    Ok([nc as u8])
}

/// Encodes the expected length (Ne) for extended length APDUs (Le1, Le2).
///
/// # Arguments
/// * `ne` - The expected length (number of expected response bytes).
fn encode_expected_length_extended(ne: usize) -> Result<[u8; 2], ApduError> {
    if ne > EXPECTED_LENGTH_WILDCARD_EXTENDED {
        return Err(ApduError::InvalidLength(format!(
            "Expected length (ne) must be in range [0, {EXPECTED_LENGTH_WILDCARD_EXTENDED}]"
        )));
    }

    Ok(if ne != EXPECTED_LENGTH_WILDCARD_EXTENDED {
        [((ne >> 8) & 0xFF) as u8, (ne & 0xFF) as u8] // l1, l2
    } else {
        [0x0, 0x0]
    })
}

/// Encodes the expected length (Ne) for short length APDUs (Le).
///
/// # Arguments
/// * `ne` - The expected length (number of expected response bytes).
fn encode_expected_length_short(ne: usize) -> Result<[u8; 1], ApduError> {
    if ne > EXPECTED_LENGTH_WILDCARD_EXTENDED {
        return Err(ApduError::InvalidLength(format!(
            "Expected length (ne) must be in range [0, {EXPECTED_LENGTH_WILDCARD_EXTENDED}]"
        )));
    }

    Ok([if ne != EXPECTED_LENGTH_WILDCARD_EXTENDED {
        if ne <= 255 {
            ne as u8
        } else {
            0x0
        }
    } else {
        0x0
    }])
}

/// Represents an APDU (Application Protocol Data Unit) Command as per ISO/IEC 7816-4.
///
///
/// Command APDU encoding options:
///
/// ```text
/// case 1:  |CLA|INS|P1 |P2 |                                 len = 4
/// case 2s: |CLA|INS|P1 |P2 |LE |                             len = 5
/// case 3s: |CLA|INS|P1 |P2 |LC |...BODY...|                  len = 6..260
/// case 4s: |CLA|INS|P1 |P2 |LC |...BODY...|LE |              len = 7..261
/// case 2e: |CLA|INS|P1 |P2 |00 |LE1|LE2|                     len = 7
/// case 3e: |CLA|INS|P1 |P2 |00 |LC1|LC2|...BODY...|          len = 8..65542
/// case 4e: |CLA|INS|P1 |P2 |00 |LC1|LC2|...BODY...|LE1|LE2|  len = 10..65544
///
/// LE, LE1, LE2 may be 0x00.
/// LC must not be 0x00 and LC1|LC2 must not be 0x00|0x00.
/// ```

#[derive(Clone)]
pub struct CardCommandApdu {
    apdu: Vec<u8>,
    data_length: usize,
    data_offset: usize,
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: Option<Vec<u8>>,
    ne: Option<usize>,
}

/// Indicates whether an APDU uses short (1-byte length fields) or extended (3-byte) encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum LengthClass {
    Short,
    Extended,
}

impl CardCommandApdu {
    /// Construct a case 1 APDU (header only).
    pub fn header_only(cla: u8, ins: u8, p1: u8, p2: u8) -> Result<Self, ApduError> {
        Self::new(cla, ins, p1, p2, None::<Vec<u8>>, None)
    }

    /// Construct a case 2 APDU (Le only) with explicit length class.
    pub fn with_expect(
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        length_class: LengthClass,
        ne: usize,
    ) -> Result<Self, ApduError> {
        match length_class {
            LengthClass::Short => {
                if ne > EXPECTED_LENGTH_WILDCARD_SHORT {
                    return Err(ApduError::InvalidLength(
                        "short APDU expected length must be in range [0, 256]".to_string(),
                    ));
                }
            }
            LengthClass::Extended => {
                if ne <= EXPECTED_LENGTH_WILDCARD_SHORT {
                    return Err(ApduError::InvalidLength("extended APDU expected length must exceed 256".to_string()));
                }
            }
        }
        Self::new(cla, ins, p1, p2, None::<Vec<u8>>, Some(ne))
    }

    /// Construct a case 3 APDU (Lc + data) with explicit length class.
    pub fn with_data<D: Into<Vec<u8>>>(
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        length_class: LengthClass,
        data: D,
    ) -> Result<Self, ApduError> {
        let data_vec = data.into();
        match length_class {
            LengthClass::Short => {
                if data_vec.is_empty() || data_vec.len() >= EXPECTED_LENGTH_WILDCARD_SHORT {
                    return Err(ApduError::InvalidLength(
                        "short APDU data length must be in range [1, 255]".to_string(),
                    ));
                }
            }
            LengthClass::Extended => {
                if data_vec.len() < EXPECTED_LENGTH_WILDCARD_SHORT {
                    return Err(ApduError::InvalidLength("extended APDU data length must be at least 256".to_string()));
                }
            }
        }
        Self::new(cla, ins, p1, p2, Some(data_vec), None::<usize>)
    }

    /// Construct a case 4 APDU (Lc + data + Le) with explicit length class.
    pub fn with_data_and_expect<D: Into<Vec<u8>>>(
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        length_class: LengthClass,
        data: D,
        ne: usize,
    ) -> Result<Self, ApduError> {
        let data_vec = data.into();
        match length_class {
            LengthClass::Short => {
                if data_vec.is_empty() || data_vec.len() >= EXPECTED_LENGTH_WILDCARD_SHORT {
                    return Err(ApduError::InvalidLength(
                        "short APDU data length must be in range [1, 255]".to_string(),
                    ));
                }
                if ne > EXPECTED_LENGTH_WILDCARD_SHORT {
                    return Err(ApduError::InvalidLength(
                        "short APDU expected length must be in range [0, 256]".to_string(),
                    ));
                }
            }
            LengthClass::Extended => {
                if data_vec.len() < EXPECTED_LENGTH_WILDCARD_SHORT {
                    return Err(ApduError::InvalidLength("extended APDU data length must be at least 256".to_string()));
                }
                if ne <= EXPECTED_LENGTH_WILDCARD_SHORT {
                    return Err(ApduError::InvalidLength("extended APDU expected length must exceed 256".to_string()));
                }
            }
        }
        Self::new(cla, ins, p1, p2, Some(data_vec), Some(ne))
    }

    /// Returns a reference to the APDU byte array.
    pub fn as_bytes(&self) -> &[u8] {
        &self.apdu
    }

    /// Returns a clone of the APDU byte array.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.apdu.clone()
    }

    /// Consumes the APDU and returns the underlying bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.apdu
    }

    /// Returns the expected length (Ne) of the response.
    pub fn expected_length(&self) -> Option<usize> {
        self.ne
    }

    /// Returns the CLA byte.
    pub fn cla(&self) -> u8 {
        self.cla
    }

    /// Returns the INS byte.
    pub fn ins(&self) -> u8 {
        self.ins
    }

    /// Returns the P1 byte.
    pub fn p1(&self) -> u8 {
        self.p1
    }

    /// Returns the P2 byte.
    pub fn p2(&self) -> u8 {
        self.p2
    }

    pub fn as_data(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }

    /// Creates a CardCommandApdu for cases 1, 2s, or 2e.
    ///
    /// # Arguments
    /// * `cla` - The class byte (CLA).
    /// * `ins` - The instruction byte (INS).
    /// * `p1` - The parameter 1 byte (P1).
    /// * `p2` - The parameter 2 byte (P2).
    /// * `ne` - The expected response length (Ne), or None for case 1.
    pub fn new_without_data(cla: u8, ins: u8, p1: u8, p2: u8, ne: Option<usize>) -> Result<Self, ApduError> {
        Self::new(cla, ins, p1, p2, None::<Vec<u8>>, ne)
    }

    /// Creates a CardCommandApdu for cases 1, 2s, 2e, 3s, 3e, 4s, or 4e.
    ///
    /// # Arguments
    /// * `cla` - The class byte (CLA).
    /// * `ins` - The instruction byte (INS).
    /// * `p1` - The parameter 1 byte (P1).
    /// * `p2` - The parameter 2 byte (P2).
    /// * `data` - The command data (body), or None for cases 1, 2s, or 2e.
    /// * `ne` - The expected response length (Ne), or None for cases 3s or 3e.
    pub fn new<D: Into<Vec<u8>>>(
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        data: Option<D>,
        ne: Option<usize>,
    ) -> Result<Self, ApduError> {
        // Validate the expected length (Ne), if provided.
        if let Some(ne_val) = ne {
            if ne_val > EXPECTED_LENGTH_WILDCARD_EXTENDED {
                return Err(ApduError::InvalidLength(format!(
                    "APDU response length must be within [0, {}]",
                    EXPECTED_LENGTH_WILDCARD_EXTENDED
                )));
            }
        }

        let mut apdu = Vec::new();
        // Append header: |CLA|INS|P1|P2|
        apdu.extend_from_slice(&[cla, ins, p1, p2]);

        let (data_length, data_offset, data_vec) = if let Some(data_into) = data {
            let data_vec = data_into.into();
            let data_length = data_vec.len();

            if data_length >= EXPECTED_LENGTH_WILDCARD_EXTENDED {
                return Err(ApduError::InvalidLength(
                    "APDU command data length must not exceed 65535 bytes".to_string(),
                ));
            }

            if let Some(ne_val) = ne {
                // Cases 4s or 4e: Both data and expected length are present.
                if data_length < EXPECTED_LENGTH_WILDCARD_SHORT && ne_val <= EXPECTED_LENGTH_WILDCARD_SHORT {
                    // Case 4s: Short data and expected length.
                    let data_offset = 5;
                    apdu.extend_from_slice(&encode_data_length_short(data_length)?);
                    apdu.extend_from_slice(&data_vec);
                    apdu.extend_from_slice(&encode_expected_length_short(ne_val)?);
                    (data_length, data_offset, Some(data_vec))
                } else {
                    // Case 4e: Extended data or expected length.
                    let data_offset = 7;
                    apdu.extend_from_slice(&encode_data_length_extended(data_length)?);
                    apdu.extend_from_slice(&data_vec);
                    apdu.extend_from_slice(&encode_expected_length_extended(ne_val)?);
                    (data_length, data_offset, Some(data_vec))
                }
            } else {
                // Cases 3s or 3e: Only data is present.
                if data_length < EXPECTED_LENGTH_WILDCARD_SHORT {
                    // Case 3s: Short data length.
                    let data_offset = 5;
                    apdu.extend_from_slice(&encode_data_length_short(data_length)?);
                    apdu.extend_from_slice(&data_vec);
                    (data_length, data_offset, Some(data_vec))
                } else {
                    // Case 3e: Extended data length.
                    let data_offset = 7;
                    apdu.extend_from_slice(&encode_data_length_extended(data_length)?);
                    apdu.extend_from_slice(&data_vec);
                    (data_length, data_offset, Some(data_vec))
                }
            }
        } else {
            // No data provided.
            if let Some(ne_val) = ne {
                // Cases 2s or 2e: Expected length only.
                if ne_val <= EXPECTED_LENGTH_WILDCARD_SHORT {
                    // Case 2s: Short expected length.
                    apdu.extend_from_slice(&encode_expected_length_short(ne_val)?);
                } else {
                    // Case 2e: Extended expected length.
                    apdu.push(0x0);
                    apdu.extend_from_slice(&encode_expected_length_extended(ne_val)?);
                }
                (0, 0, None)
            } else {
                // Case 1: Header only.
                (0, 0, None)
            }
        };

        Ok(CardCommandApdu { apdu, data_length, data_offset, cla, ins, p1, p2, data: data_vec, ne })
    }

    /// Creates a CardCommandApdu instance from a raw APDU byte array.
    ///
    /// # Arguments
    /// * `apdu` - The raw APDU byte array.
    pub fn from_bytes(apdu: &[u8]) -> Result<Self, ApduError> {
        if apdu.len() < 4 {
            return Err(ApduError::InvalidApdu("APDU must be at least 4 bytes long".to_string()));
        }

        let mut data_length = 0;
        let mut expected_length: Option<usize> = None;
        let mut data_offset = 0;

        if apdu.len() == 4 {
            // Case 1: Only the header is present.
            data_length = 0;
            expected_length = None;
            data_offset = 0;
        } else if apdu.len() == 5 {
            // Case 2s: Only expected length is present.
            let li = apdu[4] as usize;
            let ne = if li == 0 { EXPECTED_LENGTH_WILDCARD_SHORT } else { li };

            data_length = 0;
            expected_length = Some(ne);
            data_offset = 0;
        } else if (apdu[4] as usize) != 0 {
            // Short length cases: non-zero length indicator.
            let li = apdu[4] as usize;
            if apdu.len() == 4 + 1 + li {
                // Case 3s: Data only.
                data_length = li;
                expected_length = None;
                data_offset = 5;
            } else if apdu.len() == 4 + 2 + li {
                // Case 4s: Data and expected length.
                let ne = if *apdu.last().unwrap() as usize == 0 {
                    EXPECTED_LENGTH_WILDCARD_SHORT
                } else {
                    *apdu.last().unwrap() as usize
                };

                data_length = li;
                expected_length = Some(ne);
                data_offset = 5;
            } else {
                return Err(ApduError::InvalidApdu(format!(
                    "Invalid APDU: length={}, lengthIndicator={}",
                    apdu.len(),
                    li
                )));
            }
        } else {
            // Extended length cases (lengthIndicator == 0).
            if apdu.len() < 7 {
                return Err(ApduError::InvalidApdu(format!(
                    "Invalid APDU: length={}, lengthIndicator={}",
                    apdu.len(),
                    (apdu[4] as usize)
                )));
            }

            let data_length_extended = ((apdu[5] as usize) << 8) | (apdu[6] as usize);
            if apdu.len() == 7 {
                // Case 2e: Only expected length in extended format.
                let ne =
                    if data_length_extended == 0 { EXPECTED_LENGTH_WILDCARD_EXTENDED } else { data_length_extended };

                data_length = 0;
                expected_length = Some(ne);
                data_offset = 0;
            } else {
                if data_length_extended == 0 {
                    return Err(ApduError::InvalidApdu(format!(
                        "Invalid APDU: length={}, lengthIndicator={}, extendedLength={}",
                        apdu.len(),
                        (apdu[4] as usize),
                        data_length_extended
                    )));
                }

                if apdu.len() == 4 + 3 + data_length_extended {
                    // Case 3e: Data only (extended).
                    data_length = data_length_extended;
                    expected_length = None;
                    data_offset = 7;
                } else if apdu.len() == 4 + 5 + data_length_extended {
                    // Case 4e: Data and expected length (extended).
                    let off = apdu.len() - 2;
                    let expected_length_indicator = ((apdu[off] as usize) << 8) | (apdu[off + 1] as usize);
                    let ne = if expected_length_indicator == 0 {
                        EXPECTED_LENGTH_WILDCARD_EXTENDED
                    } else {
                        expected_length_indicator
                    };

                    data_length = data_length_extended;
                    expected_length = Some(ne);
                    data_offset = 7;
                } else {
                    return Err(ApduError::InvalidApdu(format!(
                        "Invalid APDU: length={}, lengthIndicator={}, extendedLength={}",
                        apdu.len(),
                        (apdu[4] as usize),
                        data_length_extended
                    )));
                }
            }
        }

        // Extract header bytes.
        let cla = apdu[0];
        let ins = apdu[1];
        let p1 = apdu[2];
        let p2 = apdu[3];

        // Extract data bytes if present.
        let data = if data_length > 0 {
            let start = data_offset;
            let end = start + data_length;
            Some(apdu[start..end].to_vec())
        } else {
            None
        };

        Ok(CardCommandApdu {
            apdu: apdu.to_vec(),
            data_length,
            data_offset,
            cla,
            ins,
            p1,
            p2,
            data,
            ne: expected_length,
        })
    }
}

impl Apdu for CardCommandApdu {
    fn bytes(&self) -> &[u8] {
        &self.apdu
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.apdu.clone()
    }
}

impl fmt::Debug for CardCommandApdu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CardCommandApdu")
            .field("cla", &self.cla)
            .field("ins", &self.ins)
            .field("p1", &self.p1)
            .field("p2", &self.p2)
            .field("data", &self.data)
            .field("ne", &self.ne)
            .field("apdu", &self.apdu)
            .finish()
    }
}

/// Represents a response APDU (Application Protocol Data Unit) received from a smart healthcard,
/// as defined by ISO/IEC 7816-4.
#[derive(Clone, Eq, PartialEq)]
pub struct CardResponseApdu {
    bytes: Vec<u8>,
}

impl CardResponseApdu {
    /// Creates a new CardResponseApdu from a byte array.
    ///
    /// # Arguments
    /// * `apdu` - The raw byte array of the received APDU.
    pub fn new(apdu: &[u8]) -> Result<Self, ApduError> {
        if apdu.len() < 2 {
            return Err(ApduError::InvalidApdu(
                "Response APDU must contain at least 2 bytes (status bytes SW1, SW2)".to_string(),
            ));
        }

        Ok(CardResponseApdu { bytes: apdu.to_vec() })
    }

    /// Convenience constructor mirroring `new`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ApduError> {
        Self::new(bytes)
    }

    /// The data bytes of the response.
    /// This is a copy of the bytes excluding the status bytes (SW1, SW2).
    pub fn to_data(&self) -> Vec<u8> {
        self.bytes[0..self.bytes.len() - 2].to_vec()
    }

    /// Returns a reference to the data bytes of the response.
    pub fn as_data(&self) -> &[u8] {
        &self.bytes[0..self.bytes.len() - 2]
    }

    /// The status byte 1 (SW1) of the response.
    /// This is the second-to-last byte of the APDU.
    pub fn sw1(&self) -> u8 {
        self.bytes[self.bytes.len() - 2]
    }

    /// The status byte 2 (SW2) of the response.
    /// This is the last byte of the APDU.
    pub fn sw2(&self) -> u8 {
        self.bytes[self.bytes.len() - 1]
    }

    /// The combined status word (SW) of the response.
    /// This is a 16-bit value formed by concatenating SW1 and SW2 (SW1 << 8 | SW2).
    pub fn sw(&self) -> u16 {
        ((self.sw1() as u16) << 8) | (self.sw2() as u16)
    }

    /// Returns a reference to the raw byte array.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns a clone of the raw byte array.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }

    /// Consumes the response and returns the underlying bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

impl Apdu for CardResponseApdu {
    fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.bytes.clone()
    }
}

impl fmt::Debug for CardResponseApdu {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sw = self.sw();
        f.debug_struct("CardResponseApdu")
            .field("sw", &format!("0x{:04X}", sw))
            .field("data_len", &(self.bytes.len() - 2))
            .field("bytes", &self.bytes)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_card_command_apdu_case1() {
        // Case 1: Header only
        let apdu = CardCommandApdu::header_only(0x00, 0xA4, 0x04, 0x00).unwrap();
        assert_eq!(apdu.to_bytes(), vec![0x00, 0xA4, 0x04, 0x00]);
        assert_eq!(apdu.data, None);
        assert_eq!(apdu.ne, None);
    }

    #[test]
    fn test_card_command_apdu_case2s() {
        // Case 2s: Header + Le (short)
        let apdu = CardCommandApdu::with_expect(0x00, 0xA4, 0x04, 0x00, LengthClass::Short, 256).unwrap();
        assert_eq!(apdu.to_bytes(), vec![0x00, 0xA4, 0x04, 0x00, 0x00]);
        assert_eq!(apdu.data, None);
        assert_eq!(apdu.ne, Some(256));
    }

    #[test]
    fn test_card_command_apdu_shape_helpers() {
        // header only
        let header = CardCommandApdu::header_only(0x00, 0xA4, 0x04, 0x00).unwrap();
        assert_eq!(header.to_bytes(), vec![0x00, 0xA4, 0x04, 0x00]);

        // expect short validation
        assert!(CardCommandApdu::with_expect(0, 0, 0, 0, LengthClass::Short, 257).is_err());

        // data extended validation
        let long_data = vec![0u8; EXPECTED_LENGTH_WILDCARD_SHORT];
        let case3e = CardCommandApdu::with_data(0x80, 0x10, 0, 0, LengthClass::Extended, long_data.clone()).unwrap();
        assert_eq!(case3e.as_data().unwrap().len(), long_data.len());

        // data+expect short validation
        assert!(CardCommandApdu::with_data_and_expect(0, 0, 0, 0, LengthClass::Short, vec![0u8; 256], 1).is_err());
    }

    #[test]
    fn test_card_response_apdu() {
        // Test response APDU with status 9000 (success)
        let response = CardResponseApdu::new(&[0x01, 0x02, 0x90, 0x00]).unwrap();
        assert_eq!(response.to_data(), vec![0x01, 0x02]);
        assert_eq!(response.sw1(), 0x90);
        assert_eq!(response.sw2(), 0x00);
        assert_eq!(response.sw(), 0x9000);
    }

    #[test]
    fn test_from_bytes() {
        let bytes = [0x00, 0xA4, 0x04, 0x00, 0x02, 0x3F, 0x00, 0x00];
        let command = CardCommandApdu::from_bytes(&bytes).unwrap();
        assert_eq!(command.cla(), 0x00);
        assert_eq!(command.ins(), 0xA4);
        assert_eq!(command.p1(), 0x04);
        assert_eq!(command.p2(), 0x00);
        assert_eq!(command.as_data(), Some(&[0x3F, 0x00][..]));
        assert_eq!(command.to_bytes(), bytes);
        assert_eq!(command.expected_length(), Some(256));

        let response_bytes = [0x6F, 0x12, 0x90, 0x00];
        let response = CardResponseApdu::from_bytes(&response_bytes).unwrap();
        assert_eq!(response.as_data(), &[0x6F, 0x12]);
        assert_eq!(response.sw(), 0x9000);
    }
}
