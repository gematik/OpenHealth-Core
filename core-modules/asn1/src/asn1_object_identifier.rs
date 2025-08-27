/*
 * Copyright 2025 gematik GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

use crate::asn1_decoder::Asn1Decoder;
use crate::asn1_encoder::{encode, Asn1Encoder};
use crate::asn1_tag::{Asn1Tag, TagClass};
use crate::error::Result as Asn1Result;
use crate::Asn1Error;
use crate::tag::Asn1Type;

/// Read ASN.1 OBJECT_IDENTIFIER.
pub fn read_object_identifier(decoder: &mut Asn1Decoder) -> Asn1Result<String> {
    decoder.advance_with_tag(
        Asn1Tag::new(TagClass::Universal, Asn1Type::ObjectIdentifier),
        |decoder| {
            let bytes = decoder.read_bytes(decoder.remaining_length())?;

            if bytes.is_empty() {
                return decoder.fail("Encoded OID cannot be empty");
            }

            let first_byte = bytes[0] as u32;
            let first = first_byte / 40;
            let second = first_byte % 40;

            let mut parts = Vec::new();

            parts.push(first);
            parts.push(second);

            // Decode the remaining bytes
            let mut value = 0u32;
            for i in 1..bytes.len() {
                let byte = bytes[i] as u32;
                value = (value << 7) | (byte & 0x7F);

                // Check if this is the last byte in the current value
                if byte & 0x80 == 0 {
                    parts.push(value);
                    value = 0;
                }
            }

            if value != 0 {
                return decoder.fail("Invalid OID encoding: unfinished encoding");
            }

            Ok(parts
                .into_iter()
                .map(|part| part.to_string())
                .collect::<Vec<String>>()
                .join("."))
        }
    )
}

/// Write ASN.1 OBJECT_IDENTIFIER.
pub fn write_object_identifier(w: &mut Asn1Encoder, oid: &str) -> Asn1Result<()> {
    w.write_tagged_object(
        Asn1Type::ObjectIdentifier as u8,
        TagClass::Universal.to_bits(),
        |inner| {
            // Teile parsen und validieren
            let parts: std::result::Result<Vec<u32>, _> = oid
                .split('.')
                .map(|part| {
                    part.parse::<u32>()
                        .map_err(|_| Asn1Error::EncodingError(format!("Invalid OID part: {}", part)))
                })
                .collect();

            let parts = parts?;

            if parts.len() < 2 {
                return Err(Asn1Error::EncodingError(
                    "OID must have at least two components".to_string(),
                ));
            }

            let first = parts[0];
            let second = parts[1];

            if first > 2 {
                return Err(Asn1Error::EncodingError(
                    "OID first part must be 0, 1, or 2".to_string(),
                ));
            }

            if second > 39 && first < 2 {
                return Err(Asn1Error::EncodingError(
                    "OID second part must be 0-39 for first part 0 or 1".to_string(),
                ));
            }

            let first_value = first * 40 + second;
            write_multi_byte(inner, first_value)?;

            for i in 2..parts.len() {
                write_multi_byte(inner, parts[i])?;
            }

            Ok(())
        },
    )
}

/// Write a multi-byte integer to the encoder.
fn write_multi_byte(w: &mut Asn1Encoder, integer: u32) -> Asn1Result<()> {
    let mut value = integer;
    let mut bytes = Vec::new();

    loop {
        bytes.push((value & 0x7F) as u8);
        value >>= 7;
        if value == 0 {
            break;
        }
    }

    for (index, byte) in bytes.iter().rev().enumerate() {
        if index < bytes.len() - 1 {
            w.write_byte(byte | 0x80);
        } else {
            w.write_byte(*byte);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1_decoder::Asn1Decoder;
    use crate::asn1_encoder::encode;

    #[test]
    fn test_read_object_identifier() {
        // OID 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
        let data = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        let result = decoder.read(read_object_identifier).unwrap();
        assert_eq!(result, "1.2.840.113549.1.1.11");
    }

    #[test]
    fn test_write_object_identifier_sha256withrsa() {
        // OID 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
        let result = encode(|w| write_object_identifier(w, "1.2.840.113549.1.1.11")).unwrap();

        assert_eq!(
            result,
            [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]
        );
    }

    #[test]
    fn test_write_object_identifier_simple() {
        // OID 1.2.840.113549
        let result = encode(|w| write_object_identifier(w, "1.2.840.113549")).unwrap();
        assert_eq!(result, [0x06, 0x06, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D]);
    }

    #[test]
    fn test_write_object_identifier_single_part_beyond_40() {
        // OID 2.100.3
        let result = encode(|w| write_object_identifier(w, "2.100.3")).unwrap();
        assert_eq!(result, [0x06, 0x03, 0x81, 0x34, 0x03]);
    }

    #[test]
    fn test_write_object_identifier_long_identifier() {
        // OID 1.2.3.4.5.265566
        let result = encode(|w| write_object_identifier(w, "1.2.3.4.5.265566")).unwrap();
        assert_eq!(result, [0x06, 0x07, 0x2A, 0x03, 0x04, 0x05, 0x90, 0x9A, 0x5E]);
    }

    #[test]
    fn test_write_object_identifier_large_first_component() {
        // OID 2.999.1
        let result = encode(|w| write_object_identifier(w, "2.999.1")).unwrap();
        assert_eq!(result, [0x06, 0x03, 0x88, 0x37, 0x01]);
    }

    #[test]
    fn test_write_object_identifier_invalid_first_part() {
        // OID first part must be 0, 1, or 2
        let err = encode(|w| write_object_identifier(w, "3.1.2"))
            .err()
            .expect("expected error");
        match err {
            Asn1Error::EncodingError(msg) => {
                assert!(msg.contains("first part"), "unexpected message: {}", msg);
            }
            _ => panic!("unexpected error type"),
        }
    }

    #[test]
    fn test_write_object_identifier_invalid_second_part_for_first() {
        // second part must be 0-39 when first part is 0 or 1
        let err = encode(|w| write_object_identifier(w, "1.40.1"))
            .err()
            .expect("expected error");
        match err {
            Asn1Error::EncodingError(msg) => {
                assert!(msg.contains("second part") || msg.contains("0-39"), "unexpected message: {}", msg);
            }
            _ => panic!("unexpected error type"),
        }
    }
}