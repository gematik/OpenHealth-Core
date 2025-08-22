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

use crate::asn1_tag::asn1_type;
use crate::asn1_date_time::{Asn1GeneralizedTime, Asn1UtcTime, GeneralizedOffset, UtcOffset};
use crate::{Asn1Error, Result as Asn1Result};

/// ASN.1 encoder for encoding data in ASN.1 format.
pub struct Asn1Encoder {
    pub buffer: Vec<u8>,
}

impl Asn1Encoder {
    /// Creates a new ASN.1 encoder.
    pub fn new() -> Self {
        Asn1Encoder {
            buffer: Vec::new(),
        }
    }

    /// Returns the buffer.
    pub fn get_buffer(&self) -> &[u8] {
        &self.buffer
    }

    /// Clears the buffer.
    pub fn clear(&mut self) {
        self.buffer.clear();
    }

    /// Appends a byte to the buffer.
    pub fn write_byte(&mut self, byte: u8) {
        self.buffer.push(byte);
    }

    /// Appends a byte array to the buffer.
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Writes an integer in big-endian format, using a variable-length encoding.
    pub fn write_int_bytes(&mut self, integer: i32) {
        let mut bytes = Vec::new();
        let mut value = integer;

        while value < -0x80 || value >= 0x80 {
            bytes.push((value & 0xFF) as u8);
            value /= 0x100;
        }
        bytes.push((value & 0xFF) as u8);

        for byte in bytes.iter().rev() {
            self.write_byte(*byte);
        }
    }

    /// Writes a length in a variable-length encoding.
    pub fn write_length(&mut self, length: usize) -> Asn1Result<()> {
        if length < 0x80 {
            // Single-byte length
            self.write_byte(length as u8);
        } else {
            // Multi-byte length
            let mut length_bytes = Vec::new();
            let mut value = length;

            while value > 0 {
                length_bytes.push((value & 0xFF) as u8);
                value >>= 8;
            }

            // Write length of length with high bit set
            self.write_byte(0x80 | length_bytes.len() as u8);

            // Write length bytes in big-endian order
            for byte in length_bytes.into_iter().rev() {
                self.write_byte(byte);
            }
        }

        Ok(())
    }

    /// Writes a tag.
    pub fn write_tag(&mut self, tag_number: u8, tag_class: u8) -> Asn1Result<()> {
        if tag_number < 0x1F {
            // Single-byte tag
            self.write_byte((tag_number as u8) | tag_class);
        } else {
            // Multi-byte tag
            self.write_byte(0x1F | tag_class);

            // Collect encoded bytes in reverse order
            let mut encoded_bytes = Vec::new();
            let mut value = tag_number;

            while value > 0 {
                encoded_bytes.push((value & 0x7F) as u8);
                value >>= 7;
            }

            // Get the length before moving the vector
            let encoded_len = encoded_bytes.len();

            // Write bytes in big-endian order with continuation bits
            for (i, byte) in encoded_bytes.into_iter().rev().enumerate() {
                if i < encoded_len - 1 {
                    self.write_byte(byte | 0x80); // Set high bit for continuation
                } else {
                    self.write_byte(byte); // Last byte without continuation bit
                }
            }
        }

        Ok(())
    }

    /// Writes the length and value of another encoder.
    pub fn write_encoder(&mut self, other: &Asn1Encoder) -> Asn1Result<()> {
        // Write length
        self.write_length(other.buffer.len())?;
        // Write value
        self.write_bytes(&other.buffer);
        Ok(())
    }

    /// Writes data using the provided block and returns the resulting vector.
    pub fn write<F>(&mut self, block: F) -> Asn1Result<Vec<u8>>
    where
        F: FnOnce(&mut Asn1Encoder) -> Asn1Result<()>,
    {
        // Clear the buffer before writing
        self.clear();
        block(self)?;
        Ok(self.buffer.clone())
    }
}

/// Write an ASN.1 tagged object.
pub fn write_tagged_object<F>(
    encoder: &mut Asn1Encoder,
    tag_number: u8,
    tag_class: u8,
    block: F
) -> Asn1Result<()>
where
    F: FnOnce(&mut Asn1Encoder) -> Asn1Result<()>,
{
    let mut inner_encoder = Asn1Encoder::new();

    block(&mut inner_encoder)?;

    encoder.buffer.push(tag_number | tag_class);
    let inner_length = inner_encoder.buffer.len();
    encoder.write_length(inner_length)?;
    encoder.buffer.extend_from_slice(&inner_encoder.buffer);

    Ok(())
}

/// Write an ASN.1 tagged object with an inner tag.
pub fn write_tagged_object_with_inner_tag(
    encoder: &mut Asn1Encoder,
    outer_tag: u8,
    outer_class: u8,
    inner_tag: u8,
    inner_class: u8,
    data: &[u8]
) -> Asn1Result<()> {
    write_tagged_object(encoder, outer_tag, outer_class, |inner_encoder| {
        write_tagged_object(inner_encoder, inner_tag, inner_class, |innermost_encoder| {
            innermost_encoder.write_bytes(data);
            Ok(())
        })
    })
}

/// Write an ASN.1 boolean.
pub fn write_boolean(encoder: &mut Asn1Encoder, value: bool) -> Asn1Result<()> {
    write_tagged_object(encoder, asn1_type::BOOLEAN, 0, |inner_encoder| {
        inner_encoder.write_byte(if value { 0xFF } else { 0x00 });
        Ok(())
    })
}

/// Write an ASN.1 integer.
pub fn write_int(encoder: &mut Asn1Encoder, value: i32) -> Asn1Result<()> {
    // Start with INTEGER tag
    encoder.write_byte(0x02); // ASN.1 INTEGER tag

    // Handle special case for zero
    if value == 0 {
        encoder.write_byte(0x01); // Length 1
        encoder.write_byte(0x00); // Value 0
        return Ok(());
    }

    // Convert the integer to bytes in big-endian format
    let mut bytes = Vec::new();
    let mut val = value;
    let is_negative = value < 0;

    // Extract bytes one at a time
    while val != 0 && val != -1 {
        bytes.push((val & 0xFF) as u8);
        val >>= 8;
    }

    // Add padding byte if needed to preserve sign
    if is_negative && (bytes.last().unwrap_or(&0) & 0x80) == 0 {
        bytes.push(0xFF);
    } else if !is_negative && (bytes.last().unwrap_or(&0) & 0x80) != 0 {
        bytes.push(0x00);
    }

    // Reverse to get big-endian order
    bytes.reverse();

    // Write length
    encoder.write_length(bytes.len())?;

    // Write integer bytes
    for byte in bytes {
        encoder.write_byte(byte);
    }

    Ok(())
}

/// Write an ASN.1 bit string.
pub fn write_bit_string(
    encoder: &mut Asn1Encoder,
    value: &[u8],
    unused_bits: u8
) -> Asn1Result<()> {
    if unused_bits > 7 {
        return Err(Asn1Error::EncodingError(format!("Invalid unused bit count: {}", unused_bits)));
    }

    write_tagged_object(encoder, asn1_type::BIT_STRING, 0, |inner_encoder| {
        inner_encoder.write_byte(unused_bits);
        inner_encoder.write_bytes(value);
        Ok(())
    })
}

/// Write an ASN.1 octet string.
pub fn write_octet_string(encoder: &mut Asn1Encoder, value: &[u8]) -> Asn1Result<()> {
    write_tagged_object(encoder, asn1_type::OCTET_STRING, 0, |inner_encoder| {
        inner_encoder.write_bytes(value);
        Ok(())
    })
}

/// Write an ASN.1 UTF8 string.
pub fn write_utf8_string(encoder: &mut Asn1Encoder, value: &str) -> Asn1Result<()> {
    write_tagged_object(encoder, asn1_type::UTF8_STRING, 0, |inner_encoder| {
        inner_encoder.write_bytes(value.as_bytes());
        Ok(())
    })
}

/// Write an ASN.1 OBJECT IDENTIFIER.
pub fn write_object_identifier(encoder: &mut Asn1Encoder, oid: &str) -> Asn1Result<()> {
    // Parse OID components
    let parts: std::result::Result<Vec<u128>, _> = oid.split('.').map(|p| p.parse::<u128>()).collect();
    let parts = match parts {
        Ok(p) => p,
        Err(_) => return Err(Asn1Error::EncodingError(format!("Invalid OID string `{}`", oid))),
    };

    if parts.len() < 2 {
        return Err(Asn1Error::EncodingError("OID must have at least two parts".to_string()));
    }

    let first = parts[0];
    let second = parts[1];

    if first > 2 {
        return Err(Asn1Error::EncodingError("First OID component must be 0, 1, or 2".to_string()));
    }
    if first < 2 && second >= 40 {
        return Err(Asn1Error::EncodingError("Second OID component must be < 40 when first is 0 or 1".to_string()));
    }

    let mut encoded: Vec<u8> = Vec::new();

    // First byte(s): 40*first + second
    let first_value = 40u128 * first + second;
    encode_base128(first_value, &mut encoded);

    // Remaining components
    for &value in parts.iter().skip(2) {
        encode_base128(value, &mut encoded);
    }

    // Wrap with OBJECT IDENTIFIER tag (0x06)
    write_tagged_object(encoder, asn1_type::OBJECT_IDENTIFIER, 0, |inner_encoder| {
        inner_encoder.write_bytes(&encoded);
        Ok(())
    })
}

/// Helper: encode integer as base-128 with continuation bits.
fn encode_base128(mut value: u128, out: &mut Vec<u8>) {
    // At least one byte
    let mut bytes = Vec::new();
    bytes.push((value & 0x7F) as u8);
    value >>= 7;
    while value > 0 {
        bytes.push(((value & 0x7F) as u8) | 0x80);
        value >>= 7;
    }
    bytes.reverse();
    out.extend_from_slice(&bytes);
}

/// Write an ASN.1 GeneralizedTime (0x18).
pub fn write_generalized_time(encoder: &mut Asn1Encoder, t: Asn1GeneralizedTime) -> Asn1Result<()> {
    let mut s = String::new();

    // YYYYMMDD
    s.push_str(&format!("{:04}{:02}{:02}", t.year, t.month, t.day));
    // HH
    s.push_str(&format!("{:02}", t.hour));
    // MM and SS when present
    if let Some(min) = t.minute {
        s.push_str(&format!("{:02}", min));
    }
    if let Some(sec) = t.second {
        s.push_str(&format!("{:02}", sec));
    }

    // Fraction
    if let Some(frac) = t.fraction_of_second {
        s.push('.');
        s.push_str(&format!("{}", frac));
    }

    // Offset
    match t.offset {
        Some(GeneralizedOffset { hours, minutes }) => {
            let sign = if hours >= 0 { '+' } else { '-' };
            let abs_h = hours.abs();
            let abs_m = minutes.abs();
            s.push(sign);
            s.push_str(&format!("{:02}{:02}", abs_h, abs_m));
        }
        None => {
            // Default to Z (UTC) if no offset
            s.push('Z');
        }
    }

    // Tag and value
    encoder.write_byte(0x18); // GeneralizedTime tag
    encoder.write_length(s.len())?;
    encoder.write_bytes(s.as_bytes());
    Ok(())
}

/// Write an ASN.1 UTCTime (0x17).
/// Write an ASN.1 UTCTime (0x17).
pub fn write_utc_time(encoder: &mut Asn1Encoder, t: Asn1UtcTime) -> Asn1Result<()> {
    let mut s = String::new();

    // YYMMDDHH
    s.push_str(&format!("{:02}{:02}{:02}{:02}", t.year, t.month, t.day, t.hour));
    // Minuten sind beim UtcTime-Modell verpflichtend (i32)
    s.push_str(&format!("{:02}", t.minute));
    if let Some(sec) = t.second {
        s.push_str(&format!("{:02}", sec));
    }

    match t.offset {
        Some(UtcOffset { hours, minutes }) => {
            let sign = if hours >= 0 { '+' } else { '-' };
            let abs_h = hours.abs();
            let abs_m = minutes.abs();
            s.push(sign);
            s.push_str(&format!("{:02}{:02}", abs_h, abs_m));
        }
        None => {
            s.push('Z');
        }
    }

    encoder.write_byte(0x17); // UTCTime tag
    encoder.write_length(s.len())?;
    encoder.write_bytes(s.as_bytes());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1_decoder::{Asn1Decoder, read_boolean, read_octet_string, read_utf8_string};

    #[test]
    fn test_write_boolean() {
        let mut encoder = Asn1Encoder::new();

        // Encode true
        let data = encoder.write(|encoder| write_boolean(encoder, true)).unwrap();

        // Verify encoding
        assert_eq!(data, [0x01, 0x01, 0xFF]);

        // Decode and verify value
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        let result = read_boolean(&mut decoder).unwrap();
        assert_eq!(result, true);

        // Encode false
        let data = encoder.write(|encoder| write_boolean(encoder, false)).unwrap();

        // Verify encoding
        assert_eq!(data, [0x01, 0x01, 0x00]);

        // Decode and verify value
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        let result = read_boolean(&mut decoder).unwrap();
        assert_eq!(result, false);
    }

    #[test]
    fn test_write_int_zero() {
        let mut encoder = Asn1Encoder::new();
        write_int(&mut encoder, 0).unwrap();
        assert_eq!(encoder.get_buffer(), &[0x02, 0x01, 0x00]);
    }

    #[test]
    fn test_write_int_positive() {
        let mut encoder = Asn1Encoder::new();
        write_int(&mut encoder, 42).unwrap();
        assert_eq!(encoder.get_buffer(), &[0x02, 0x01, 0x2A]);
    }

    #[test]
    fn test_write_int_negative() {
        let mut encoder = Asn1Encoder::new();
        write_int(&mut encoder, -42).unwrap();
        assert_eq!(encoder.get_buffer(), &[0x02, 0x01, 0xD6]);
    }

    #[test]
    fn test_write_octet_string() {
        let mut encoder = Asn1Encoder::new();

        let test_data = vec![0x01, 0x02, 0x03, 0xFF];

        // Encode
        let data = encoder.write(|encoder| write_octet_string(encoder, &test_data)).unwrap();

        // Decode
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        let result = read_octet_string(&mut decoder).unwrap();

        assert_eq!(result, test_data);
    }

    #[test]
    fn test_write_utf8_string() {
        let mut encoder = Asn1Encoder::new();

        let test_str = "Hello, ASN.1!";

        // Encode
        let data = encoder.write(|encoder| write_utf8_string(encoder, test_str)).unwrap();

        // Decode
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        let result = read_utf8_string(&mut decoder).unwrap();

        assert_eq!(result, test_str);
    }

    #[test]
    fn test_write_tagged_object() {
        let mut encoder = Asn1Encoder::new();

        // Write a context-specific tagged object containing an integer
        let tag_number = 3;
        let tag_class = 0x80; // CONTEXT_SPECIFIC

        let data = encoder.write(|encoder| {
            write_tagged_object(encoder, tag_number, tag_class, |inner_encoder| {
                write_int(inner_encoder, 42)
            })
        }).unwrap();

        // Verify outer tag
        assert_eq!(data[0], tag_number | tag_class);
        // Verify inner content starts with INTEGER (02 01 2A)
        assert_eq!(data[2], 0x02); // INTEGER tag
        assert_eq!(data[3], 0x01); // Length of integer value
        assert_eq!(data[4], 0x2A); // Integer value (42)
    }

    #[test]
    fn test_write_tagged_object_with_inner_tag() {
        let mut encoder = Asn1Encoder::new();

        // Write a context-specific tagged object containing an octet string
        let outer_tag = 3;
        let outer_class = 0x80; // CONTEXT_SPECIFIC
        let inner_tag = asn1_type::OCTET_STRING;
        let inner_class = 0;
        let test_data = &[0x01, 0x02, 0x03];

        let data = encoder.write(|encoder| {
            write_tagged_object_with_inner_tag(
                encoder,
                outer_tag,
                outer_class,
                inner_tag,
                inner_class,
                test_data
            )
        }).unwrap();

        // Verify outer tag
        assert_eq!(data[0], outer_tag | outer_class);

        // Verify inner tag and length
        assert_eq!(data[2], (inner_tag as u8));
        assert_eq!(data[3], 3); // Length of test_data

        // Verify data
        assert_eq!(&data[4..], test_data);
    }
}