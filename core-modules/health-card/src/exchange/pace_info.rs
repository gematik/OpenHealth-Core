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

use crate::asn1::{
    asn1_decoder::Asn1Decoder,
    asn1_encoder::encode,
    asn1_object_identifier::write_object_identifier,
    read_int,
    Asn1Error,
    Asn1Tag,
    TagClass,
    asn1_type,
};
use crate::crypto::key::ec_key::EcCurve;
use std::collections::HashMap;
use std::fmt;
use once_cell::sync::Lazy;

/// Error type for PACE information parsing
#[derive(Debug)]
pub enum PaceInfoError {
    Asn1Error(Asn1Error),
    UnsupportedParameterId(i64),
}

impl fmt::Display for PaceInfoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PaceInfoError::Asn1Error(e) => write!(f, "ASN.1 error: {}", e),
            PaceInfoError::UnsupportedParameterId(id) => write!(f, "Unsupported parameter ID: {}", id),
        }
    }
}

impl std::error::Error for PaceInfoError {}

impl From<Asn1Error> for PaceInfoError {
    fn from(error: Asn1Error) -> Self {
        PaceInfoError::Asn1Error(error)
    }
}

/// Represents the PACE (Password Authenticated Connection Establishment) information
#[derive(Debug)]
pub struct PaceInfo {
    /// The protocol identifier (OID)
    pub protocol_id: String,
    /// The elliptic curve to use
    pub curve: EcCurve,
}

impl PaceInfo {
    /// Creates a new PaceInfo with the given protocol ID and curve
    pub fn new(protocol_id: String, curve: EcCurve) -> Self {
        Self { protocol_id, curve }
    }

    /// Returns the protocol ID bytes without the tag and length
    pub fn protocol_id_bytes(&self) -> Vec<u8> {
        // Encode full TLV first
        let encoded = encode(|w| {
            write_object_identifier(w, &self.protocol_id)
        }).expect("OID encoding must not fail");
        // Strip tag (1+ bytes) + length (1+ bytes) in a DER-compliant way
        // Tag is at least 1 byte; for UNIVERSAL OBJECT IDENTIFIER it's one byte (0x06),
        // but we still parse length generically.
        let mut idx = 1; // skip first tag octet; high-tag-number not expected for OID
        // parse length octets
        if encoded[idx] & 0x80 == 0 {
            // short form: one length byte
            idx += 1;
        } else {
            // long form
            let n = (encoded[idx] & 0x7F) as usize; // number of subsequent length bytes
            idx += 1 + n;
        }
        encoded[idx..].to_vec()
    }
}

/// Maps standardized parameter IDs to their corresponding elliptic curves
/// as specified in BSI TR-03110 Part 3, Appendix A.2.1.1.
/// The curves are defined in RFC 5639.
static SUPPORTED_CURVES: Lazy<HashMap<i64, EcCurve>> = Lazy::new(|| {
    let mut map = HashMap::new();
    map.insert(13, EcCurve::BrainpoolP256r1);
    map.insert(16, EcCurve::BrainpoolP384r1);
    map.insert(17, EcCurve::BrainpoolP512r1);
    map
});

/// Parses the PACE information from an ASN.1 encoded byte array.
///
/// This function extracts:
/// 1. The protocol identifier (OID).
/// 2. The parameter ID, which determines the elliptic curve
///    as specified BSI TR-03110 Part 3 Section A.1.1.1
///
/// # Arguments
///
/// * `asn1` - The ASN.1 encoded PACE information.
///
/// # Returns
///
/// A `Result` containing either a `PaceInfo` object or a `PaceInfoError`.
pub fn parse_pace_info(asn1: &[u8]) -> Result<PaceInfo, PaceInfoError> {
    let mut decoder = Asn1Decoder::new(asn1)?;

    decoder.read(|reader| {
        // SET (constructed)
        reader.advance_with_tag(
            Asn1Tag::new(TagClass::Universal, asn1_type::SET as u32).with_constructed(true),
            |reader| {
                // SEQUENCE (constructed)
                reader.advance_with_tag(
                    Asn1Tag::new(TagClass::Universal, asn1_type::SEQUENCE as u32).with_constructed(true),
                    |reader| {
                        // 1) protocol identifier (OID)
                        let protocol_id = {
                            // use the free helper to read an OBJECT IDENTIFIER
                            crate::asn1::asn1_object_identifier::read_object_identifier(reader)?
                        };

                        // 2) ignore first INTEGER
                        let _ = read_int(reader)?;

                        // 3) read parameter-id INTEGER and map to curve
                        let parameter_id = read_int(reader)? as i64;
                        let curve = SUPPORTED_CURVES
                            .get(&parameter_id)
                            .cloned()
                            .ok_or_else(|| PaceInfoError::UnsupportedParameterId(parameter_id))?;

                        // ensure we consumed the SEQUENCE fully
                        reader.skip_to_end()?;

                        Ok(PaceInfo::new(protocol_id, curve))
                    },
                )
            },
        )
    }).map_err(PaceInfoError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Converts a hex string with spaces to a byte vector
    fn hex_to_bytes(hex_str: &str) -> Vec<u8> {
        let hex_str = hex_str.replace(" ", "");
        (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Converts bytes to a hex string with spaces
    fn bytes_to_hex_with_spaces(bytes: &[u8]) -> String {
        bytes.iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<String>>()
            .join(" ")
    }

    #[test]
    fn pace_info_extraction_validate_protocol_id_and_protocol_bytes_with_spaces() {
        let card_access_bytes = "31 14 30 12 06 0A 04 00 7F 00 07 02 02 04 02 02 02 01 02 02 01 0D";
        let expected_protocol_id = "0.4.0.127.0.7.2.2.4.2.2";
        let expected_pace_info_protocol_bytes = "04 00 7F 00 07 02 02 04 02 02";

        let pace_info = parse_pace_info(&hex_to_bytes(card_access_bytes)).expect("Failed to parse PACE info");

        assert_eq!(expected_protocol_id, pace_info.protocol_id);
        assert_eq!(
            expected_pace_info_protocol_bytes,
            bytes_to_hex_with_spaces(&pace_info.protocol_id_bytes())
        );
        assert_eq!(pace_info.curve, EcCurve::BrainpoolP256r1);
    }

    #[test]
    fn test_unsupported_parameter_id() {
        // Same as above but with parameter ID 42 (unsupported)
        let invalid_bytes = "31 14 30 12 06 0A 04 00 7F 00 07 02 02 04 02 02 02 01 02 02 01 2A";

        let result = parse_pace_info(&hex_to_bytes(invalid_bytes));

        assert!(result.is_err());
        match result {
            Err(PaceInfoError::UnsupportedParameterId(id)) => assert_eq!(id, 42),
            _ => panic!("Expected UnsupportedParameterId error"),
        }
    }

    #[test]
    fn test_malformed_asn1() {
        // Malformed ASN.1 (truncated)
        let invalid_bytes = "31 14 30 12 06 0A 04 00 7F 00";

        let result = parse_pace_info(&hex_to_bytes(invalid_bytes));

        assert!(result.is_err());
        assert!(matches!(result, Err(PaceInfoError::Asn1Error(_))));
    }
}