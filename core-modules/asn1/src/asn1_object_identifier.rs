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

use crate::asn1_decoder::{Asn1Decoder, Asn1DecoderError};
use crate::asn1_encoder::Asn1Encoder;
use crate::asn1_tag::asn1_type;

/// Read ASN.1 OBJECT_IDENTIFIER.
pub fn read_object_identifier(decoder: &mut Asn1Decoder) -> Result<String, Asn1DecoderError> {
    decoder.advance_with_tag(asn1_type::OBJECT_IDENTIFIER as u32, 0, |decoder| {
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

        Ok(parts.into_iter()
            .map(|part| part.to_string())
            .collect::<Vec<String>>()
            .join("."))
    })
}

/// Write ASN.1 OBJECT_IDENTIFIER.
pub fn write_object_identifier(encoder: &mut Asn1Encoder, oid: &str) -> Result<(), Asn1DecoderError> {
    crate::asn1_encoder::write_tagged_object(encoder, asn1_type::OBJECT_IDENTIFIER, 0, |inner_encoder| {
        let parts: Result<Vec<u32>, _> = oid.split('.')
            .map(|part| {
                part.parse::<u32>().map_err(|_| {
                    Asn1DecoderError::new(format!("Invalid OID part: {}", part))
                })
            })
            .collect();

        let parts = parts?;

        if parts.len() < 2 {
            return Err(Asn1DecoderError::new("OID must have at least two components"));
        }

        let first = parts[0];
        let second = parts[1];

        if first > 2 {
            return Err(Asn1DecoderError::new("OID first part must be 0, 1, or 2"));
        }

        if second > 39 && first < 2 {
            return Err(Asn1DecoderError::new("OID second part must be 0-39 for first part 0 or 1"));
        }

        // Encode the first two parts as a single byte
        let first_byte = first * 40 + second;

        write_multi_byte(inner_encoder, first_byte)?;

        // Encode the remaining parts
        for i in 2..parts.len() {
            write_multi_byte(inner_encoder, parts[i])?;
        }

        Ok(())
    })
}

/// Helper function to write a multi-byte integer value with 7 bits per byte.
fn write_multi_byte(encoder: &mut Asn1Encoder, integer: u32) -> Result<(), Asn1DecoderError> {
    let mut value = integer;
    let mut bytes = Vec::new();

    loop {
        bytes.push((value & 0x7F) as u8);
        value >>= 7;
        if value == 0 {
            break;
        }
    }

    // Write bytes in reverse order, setting the MSB for all but the last byte
    for (index, byte) in bytes.iter().rev().enumerate() {
        if index < bytes.len() - 1 {
            // All but the last byte have the high bit set
            encoder.write_byte(byte | 0x80);
        } else {
            // Last byte has high bit clear
            encoder.write_byte(*byte);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1_encoder::Asn1Encoder;

    #[test]
    fn test_read_object_identifier() {
        // Test OID 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
        let data = [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        let result = decoder.read(read_object_identifier).unwrap();
        assert_eq!(result, "1.2.840.113549.1.1.11");
    }

    #[test]
    fn test_write_object_identifier() {
        // Test OID 1.2.840.113549.1.1.11 (sha256WithRSAEncryption)
        let mut encoder = Asn1Encoder::new();
        let result = encoder.write(|scope| {
            write_object_identifier(scope, "1.2.840.113549.1.1.11")
        }).unwrap();

        assert_eq!(
            result,
            [0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]
        );
    }
}