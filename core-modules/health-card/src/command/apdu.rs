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

use std::error::Error;
use std::fmt;

pub const EXPECTED_LENGTH_WILDCARD_EXTENDED: usize = 65536;

pub const EXPECTED_LENGTH_WILDCARD_SHORT: usize = 256;

#[derive(Debug)]
pub enum ApduError {
    InvalidHeader(String),
    InvalidLength(String),
    InvalidApdu(String),
}

impl fmt::Display for ApduError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApduError::InvalidHeader(msg) => write!(f, "Invalid APDU header: {}", msg),
            ApduError::InvalidLength(msg) => write!(f, "Invalid APDU length: {}", msg),
            ApduError::InvalidApdu(msg) => write!(f, "Invalid APDU: {}", msg),
        }
    }
}

impl Error for ApduError {}

/// Common trait for all APDU types
pub trait Apdu {
    fn bytes(&self) -> &[u8];
    fn to_bytes(&self) -> Vec<u8>;
}

/// Encodes the data length (Nc) for extended length APDUs (Lc1, Lc2).
///
/// # Arguments
/// * `nc` - The data length (number of data bytes).
fn encode_data_length_extended(nc: usize) -> [u8; 3] {
    [0x0, ((nc >> 8) & 0xFF) as u8, (nc & 0xFF) as u8]
}

/// Encodes the data length (Nc) for short length APDUs (Lc).
///
/// # Arguments
/// * `nc` - The data length (number of data bytes).
fn encode_data_length_short(nc: usize) -> [u8; 1] {
    assert!(
        nc <= 255,
        "Data length (nc) must be in range [0, 255] for short APDUs"
    );
    [nc as u8]
}

/// Encodes the expected length (Ne) for extended length APDUs (Le1, Le2).
///
/// # Arguments
/// * `ne` - The expected length (number of expected response bytes).
fn encode_expected_length_extended(ne: usize) -> [u8; 2] {
    assert!(
        ne <= EXPECTED_LENGTH_WILDCARD_EXTENDED,
        "Expected length (ne) must be in range [0, {}]",
        EXPECTED_LENGTH_WILDCARD_EXTENDED
    );

    if ne != EXPECTED_LENGTH_WILDCARD_EXTENDED {
        [((ne >> 8) & 0xFF) as u8, (ne & 0xFF) as u8] // l1, l2
    } else {
        [0x0, 0x0]
    }
}

/// Encodes the expected length (Ne) for short length APDUs (Le).
///
/// # Arguments
/// * `ne` - The expected length (number of expected response bytes).
fn encode_expected_length_short(ne: usize) -> [u8; 1] {
    assert!(
        ne <= EXPECTED_LENGTH_WILDCARD_EXTENDED,
        "Expected length (ne) must be in range [0, {}]",
        EXPECTED_LENGTH_WILDCARD_EXTENDED
    );

    [if ne != EXPECTED_LENGTH_WILDCARD_EXTENDED {
        if ne <= 255 {
            ne as u8
        } else {
            0x0
        }
    } else {
        0x0
    }]
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

impl CardCommandApdu {
    /// Returns a reference to the APDU byte array.
    pub fn apdu_ref(&self) -> &[u8] {
        &self.apdu
    }

    /// Returns a clone of the APDU byte array.
    pub fn apdu(&self) -> Vec<u8> {
        self.apdu.clone()
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

    pub fn data_ref(&self) -> Option<&[u8]> {
        self.data.as_deref()
    }

    pub fn builder() -> CardCommandApduBuilder {
        CardCommandApduBuilder::new()
    }

    /// Creates a CardCommandApdu for cases 1, 2s, or 2e.
    ///
    /// # Arguments
    /// * `cla` - The class byte (CLA).
    /// * `ins` - The instruction byte (INS).
    /// * `p1` - The parameter 1 byte (P1).
    /// * `p2` - The parameter 2 byte (P2).
    /// * `ne` - The expected response length (Ne), or None for case 1.
    pub fn of_options_without_data(
        cla: u8,
        ins: u8,
        p1: u8,
        p2: u8,
        ne: Option<usize>,
    ) -> Result<Self, ApduError> {
        Self::of_options(cla, ins, p1, p2, None::<Vec<u8>>, ne)
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
    pub fn of_options<D: Into<Vec<u8>>>(
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
                if data_length < EXPECTED_LENGTH_WILDCARD_SHORT
                    && ne_val <= EXPECTED_LENGTH_WILDCARD_SHORT
                {
                    // Case 4s: Short data and expected length.
                    let data_offset = 5;
                    apdu.extend_from_slice(&encode_data_length_short(data_length));
                    apdu.extend_from_slice(&data_vec);
                    apdu.extend_from_slice(&encode_expected_length_short(ne_val));
                    (data_length, data_offset, Some(data_vec))
                } else {
                    // Case 4e: Extended data or expected length.
                    let data_offset = 7;
                    apdu.extend_from_slice(&encode_data_length_extended(data_length));
                    apdu.extend_from_slice(&data_vec);
                    apdu.extend_from_slice(&encode_expected_length_extended(ne_val));
                    (data_length, data_offset, Some(data_vec))
                }
            } else {
                // Cases 3s or 3e: Only data is present.
                if data_length < EXPECTED_LENGTH_WILDCARD_SHORT {
                    // Case 3s: Short data length.
                    let data_offset = 5;
                    apdu.extend_from_slice(&encode_data_length_short(data_length));
                    apdu.extend_from_slice(&data_vec);
                    (data_length, data_offset, Some(data_vec))
                } else {
                    // Case 3e: Extended data length.
                    let data_offset = 7;
                    apdu.extend_from_slice(&encode_data_length_extended(data_length));
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
                    apdu.extend_from_slice(&encode_expected_length_short(ne_val));
                } else {
                    // Case 2e: Extended expected length.
                    apdu.push(0x0);
                    apdu.extend_from_slice(&encode_expected_length_extended(ne_val));
                }
                (0, 0, None)
            } else {
                // Case 1: Header only.
                (0, 0, None)
            }
        };

        Ok(CardCommandApdu {
            apdu,
            data_length,
            data_offset,
            cla,
            ins,
            p1,
            p2,
            data: data_vec,
            ne,
        })
    }

    /// Creates a CardCommandApdu instance from a raw APDU byte array.
    ///
    /// # Arguments
    /// * `apdu` - The raw APDU byte array.
    pub fn of_apdu(apdu: &[u8]) -> Result<Self, ApduError> {
        if apdu.len() < 4 {
            return Err(ApduError::InvalidApdu(
                "APDU must be at least 4 bytes long".to_string(),
            ));
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
            let ne = if li == 0 {
                EXPECTED_LENGTH_WILDCARD_SHORT
            } else {
                li
            };

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
                let ne = if data_length_extended == 0 {
                    EXPECTED_LENGTH_WILDCARD_EXTENDED
                } else {
                    data_length_extended
                };

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
                    let expected_length_indicator =
                        ((apdu[off] as usize) << 8) | (apdu[off + 1] as usize);
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

    /// Creates a CardCommandApdu from a byte array.
    ///
    /// This is an additional function that allows passing the APDU as a byte array.
    ///
    /// # Arguments
    /// * `byte_array` - The raw APDU byte array.
    pub fn from_byte_array(byte_array: &[u8]) -> Result<Self, ApduError> {
        Self::of_apdu(byte_array)
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

/// Builder for CardCommandApdu to make creating complex APDUs easier
pub struct CardCommandApduBuilder {
    cla: u8,
    ins: u8,
    p1: u8,
    p2: u8,
    data: Option<Vec<u8>>,
    ne: Option<usize>,
}

impl CardCommandApduBuilder {
    /// Creates a new CardCommandApduBuilder with default values.
    pub fn new() -> Self {
        Self {
            cla: 0,
            ins: 0,
            p1: 0,
            p2: 0,
            data: None,
            ne: None,
        }
    }

    /// Sets the CLA byte.
    pub fn cla(mut self, cla: u8) -> Self {
        self.cla = cla;
        self
    }

    /// Sets the INS byte.
    pub fn ins(mut self, ins: u8) -> Self {
        self.ins = ins;
        self
    }

    /// Sets the P1 byte.
    pub fn p1(mut self, p1: u8) -> Self {
        self.p1 = p1;
        self
    }

    /// Sets the P2 byte.
    pub fn p2(mut self, p2: u8) -> Self {
        self.p2 = p2;
        self
    }

    /// Sets the data field.
    pub fn data<D: Into<Vec<u8>>>(mut self, data: D) -> Self {
        self.data = Some(data.into());
        self
    }

    /// Sets the expected length (Ne).
    pub fn expected_length(mut self, ne: usize) -> Self {
        self.ne = Some(ne);
        self
    }

    /// Builds the CardCommandApdu.
    pub fn build(self) -> Result<CardCommandApdu, ApduError> {
        CardCommandApdu::of_options(self.cla, self.ins, self.p1, self.p2, self.data, self.ne)
    }
}

impl Default for CardCommandApduBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Represents a response APDU (Application Protocol Data Unit) received from a smart health-card,
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

        Ok(CardResponseApdu {
            bytes: apdu.to_vec(),
        })
    }

    /// Creates a CardResponseApdu from a byte array.
    ///
    /// This is an additional function that allows passing the APDU as a byte array.
    ///
    /// # Arguments
    /// * `byte_array` - The raw APDU byte array.
    pub fn from_byte_array(byte_array: &[u8]) -> Result<Self, ApduError> {
        Self::new(byte_array)
    }

    /// The data bytes of the response.
    /// This is a copy of the bytes excluding the status bytes (SW1, SW2).
    pub fn data(&self) -> Vec<u8> {
        self.bytes[0..self.bytes.len() - 2].to_vec()
    }

    /// Returns a reference to the data bytes of the response.
    pub fn data_ref(&self) -> &[u8] {
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
    pub fn bytes_ref(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns a clone of the raw byte array.
    pub fn bytes(&self) -> Vec<u8> {
        self.bytes.clone()
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
        let apdu =
            CardCommandApdu::of_options(0x00, 0xA4, 0x04, 0x00, None::<Vec<u8>>, None).unwrap();
        assert_eq!(apdu.apdu(), vec![0x00, 0xA4, 0x04, 0x00]);
        assert_eq!(apdu.data, None);
        assert_eq!(apdu.ne, None);
    }

    #[test]
    fn test_card_command_apdu_case2s() {
        // Case 2s: Header + Le (short)
        let apdu = CardCommandApdu::of_options(0x00, 0xA4, 0x04, 0x00, None::<Vec<u8>>, Some(256))
            .unwrap();
        assert_eq!(apdu.apdu(), vec![0x00, 0xA4, 0x04, 0x00, 0x00]);
        assert_eq!(apdu.data, None);
        assert_eq!(apdu.ne, Some(256));
    }

    #[test]
    fn test_card_command_apdu_builder() {
        let apdu = CardCommandApdu::builder()
            .cla(0x00)
            .ins(0xA4)
            .p1(0x04)
            .p2(0x00)
            .data(vec![0x3F, 0x00])
            .expected_length(256)
            .build()
            .unwrap();

        assert_eq!(apdu.cla(), 0x00);
        assert_eq!(apdu.ins(), 0xA4);
        assert_eq!(apdu.p1(), 0x04);
        assert_eq!(apdu.p2(), 0x00);
        assert_eq!(apdu.data_ref(), Some(&[0x3F, 0x00][..]));
        assert_eq!(apdu.expected_length(), Some(256));
    }

    #[test]
    fn test_card_response_apdu() {
        // Test response APDU with status 9000 (success)
        let response = CardResponseApdu::new(&[0x01, 0x02, 0x90, 0x00]).unwrap();
        assert_eq!(response.data(), vec![0x01, 0x02]);
        assert_eq!(response.sw1(), 0x90);
        assert_eq!(response.sw2(), 0x00);
        assert_eq!(response.sw(), 0x9000);
    }

    #[test]
    fn test_from_byte_array() {
        let bytes = [0x00, 0xA4, 0x04, 0x00, 0x02, 0x3F, 0x00, 0x00];
        let command = CardCommandApdu::from_byte_array(&bytes).unwrap();
        assert_eq!(command.cla(), 0x00);
        assert_eq!(command.ins(), 0xA4);
        assert_eq!(command.p1(), 0x04);
        assert_eq!(command.p2(), 0x00);
        assert_eq!(command.data_ref(), Some(&[0x3F, 0x00][..]));
        assert_eq!(command.expected_length(), Some(256));

        let response_bytes = [0x6F, 0x12, 0x90, 0x00];
        let response = CardResponseApdu::from_byte_array(&response_bytes).unwrap();
        assert_eq!(response.data_ref(), &[0x6F, 0x12]);
        assert_eq!(response.sw(), 0x9000);
    }
}
