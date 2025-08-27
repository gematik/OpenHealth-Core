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

use crate::asn1_tag::Asn1Type;
use crate::{Asn1Error, Result as Asn1Result};


/// One-shot encoding entry point: creates a scoped writer and returns DER bytes
pub fn encode<F>(f: F) -> Asn1Result<Vec<u8>>
where
    F: FnOnce(&mut Asn1Encoder) -> Asn1Result<()>,
{
    let mut w = Asn1Encoder::new();
    f(&mut w)?;
    Ok(w.finish())
}

/// Trait for values that can be encoded to DER (Distinguished Encoding Rules).
pub trait Asn1Encode {
    /// Write the *value* (V) part into the provided encoder. Tag & length are handled by `encode_der`.
    fn encode_value(&self, encoder: &mut Asn1Encoder) -> Asn1Result<()>;
    /// The ASN.1 universal tag for this type (e.g., 0x01 BOOL, 0x02 INTEGER, ...).
    fn tag() -> u8;

    /// Encode with tag + length + value into a fresh `Vec<u8>`.
    fn encode_der(&self) -> Asn1Result<Vec<u8>> {
        let mut e = Asn1Encoder::new();
        e.write(|enc| {
            enc.write_byte(Self::tag());
            // write value to a temporary to compute length
            let mut inner = Asn1Encoder::new();
            self.encode_value(&mut inner)?;
            enc.write_length(inner.buffer.len())?;
            enc.write_bytes(&inner.buffer);
            Ok(())
        })
    }
}

impl Asn1Encode for bool {
    fn encode_value(&self, encoder: &mut Asn1Encoder) -> Asn1Result<()> {
        encoder.write_byte(if *self { 0xFF } else { 0x00 });
        Ok(())
    }
    fn tag() -> u8 { u8::from(Asn1Type::Boolean) }
}

impl Asn1Encode for i32 {
    fn encode_value(&self, encoder: &mut Asn1Encoder) -> Asn1Result<()> {
        if *self == 0 { encoder.write_byte(0x00); return Ok(()); }
        let mut bytes = Vec::new();
        let mut val = *self;
        let is_negative = val < 0;
        while val != 0 && val != -1 {
            bytes.push((val & 0xFF) as u8);
            val >>= 8;
        }
        if is_negative && (bytes.last().unwrap_or(&0) & 0x80) == 0 { bytes.push(0xFF); }
        else if !is_negative && (bytes.last().unwrap_or(&0) & 0x80) != 0 { bytes.push(0x00); }
        bytes.reverse();
        for b in bytes { encoder.write_byte(b); }
        Ok(())
    }
    fn tag() -> u8 { 0x02 }
}

impl Asn1Encode for &str {
    fn encode_value(&self, encoder: &mut Asn1Encoder) -> Asn1Result<()> {
        encoder.write_bytes(self.as_bytes());
        Ok(())
    }
    fn tag() -> u8 { u8::from(Asn1Type::Utf8String) }
}

impl Asn1Encode for &[u8] {
    fn encode_value(&self, encoder: &mut Asn1Encoder) -> Asn1Result<()> {
        encoder.write_bytes(self);
        Ok(())
    }
    fn tag() -> u8 { u8::from(Asn1Type::OctetString) }
}

/// Encodes a boolean to DER (01 01 FF/00)
pub fn encode_boolean(value: bool) -> Asn1Result<Vec<u8>> { value.encode_der() }
/// Encodes an INTEGER to DER
pub fn encode_int(value: i32) -> Asn1Result<Vec<u8>> { value.encode_der() }
/// Encodes an OCTET STRING to DER
pub fn encode_octet_string(value: &[u8]) -> Asn1Result<Vec<u8>> { value.encode_der() }
/// Encodes a UTF8String to DER
pub fn encode_utf8_string(value: &str) -> Asn1Result<Vec<u8>> { value.encode_der() }

/// ASN.1 encoder for encoding data in ASN.1 format.
pub struct Asn1Encoder {
    buffer: Vec<u8>,
}

impl Asn1Encoder {
    /// Creates a new ASN.1 encoder.
    pub(crate) fn new() -> Self {
        Asn1Encoder {
            buffer: Vec::new(),
        }
    }

    /// Finish and return the encoded bytes (takes ownership)
    pub fn finish(self) -> Vec<u8> { self.buffer }

    pub(crate) fn get_buffer(&self) -> &[u8] {
        &self.buffer
    }

    pub(crate) fn clear(&mut self) {
        self.buffer.clear();
    }

    pub fn write_byte(&mut self, byte: u8) {
        self.buffer.push(byte);
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }


    pub(crate) fn write_length(&mut self, length: usize) -> Asn1Result<()> {
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

    pub(crate) fn write_tag(&mut self, tag_number: u8, tag_class: u8) -> Asn1Result<()> {
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

    pub(crate) fn write<F>(&mut self, block: F) -> Asn1Result<Vec<u8>>
    where
        F: FnOnce(&mut Asn1Encoder) -> Asn1Result<()>,
    {
        self.clear();
        block(self)?;
        Ok(self.buffer.clone())
    }

    pub fn write_tagged_object<F>(&mut self, tag_number: u8, tag_class: u8, f: F) -> Asn1Result<()>
    where
        F: FnOnce(&mut Asn1Encoder) -> Asn1Result<()>,
    {
        // Tag
        self.write_tag(tag_number, tag_class)?;
        // Inner scope
        let mut inner = Asn1Encoder::new();
        f(&mut inner)?;
        let inner_buf = inner.finish();
        // Length + value
        self.write_length(inner_buf.len())?;
        self.write_bytes(&inner_buf);
        Ok(())
    }

    /// Write a full ASN.1 tag (class + constructed + number) using the structured tag type.
    pub fn write_tag_struct(&mut self, tag: crate::asn1_tag::Asn1Tag) -> Asn1Result<()> {
        self.write_bytes(&[tag.class.to_bits() | tag.pc_bits() | (tag.asn1_type as u8)]);
        Ok(())
    }

    /// Write a TLV using a structured tag and a closure for the value bytes.
    /// The closure writes into a temporary inner encoder; its length is then encoded automatically.
    pub fn write_tagged(
        &mut self,
        tag: crate::asn1_tag::Asn1Tag,
        f: impl FnOnce(&mut Asn1Encoder) -> Asn1Result<()>,
    ) -> Asn1Result<()> {
        self.write_tag_struct(tag)?;
        let mut inner = Asn1Encoder::new();
        f(&mut inner)?;
        let inner_buf = inner.finish();
        self.write_length(inner_buf.len())?;
        self.write_bytes(&inner_buf);
        Ok(())
    }
    /// Write a primitive TLV directly from raw value bytes using a structured tag.
    pub fn write_primitive(&mut self, tag: crate::asn1_tag::Asn1Tag, value: &[u8]) -> Asn1Result<()> {
        self.write_tag_struct(tag)?;
        self.write_length(value.len())?;
        self.write_bytes(value);
        Ok(())
    }

    /// Helper: DER-encode a signed 32-bit integer to minimal two's complement bytes.
    fn encode_integer_i32_bytes(n: i32) -> Vec<u8> {
        if n == 0 { return vec![0x00]; }
        let mut bytes = n.to_be_bytes().to_vec();
        if n >= 0 {
            while bytes.len() > 1 && bytes[0] == 0x00 && (bytes[1] & 0x80) == 0 { bytes.remove(0); }
        } else {
            while bytes.len() > 1 && bytes[0] == 0xFF && (bytes[1] & 0x80) == 0x80 { bytes.remove(0); }
        }
        bytes
    }

    /// Write an ASN.1 INTEGER (UNIVERSAL 0x02) with minimal DER encoding.
    pub fn write_int(&mut self, n: i32) -> Asn1Result<()> {
        let value = Self::encode_integer_i32_bytes(n);
        let tag = crate::asn1_tag::Asn1Tag::new(crate::asn1_tag::TagClass::Universal, Asn1Type::Integer);
        self.write_primitive(tag, &value)
    }

    /// Write an ASN.1 OCTET STRING (UNIVERSAL 0x04).
    pub fn write_octet_string(&mut self, data: &[u8]) -> Asn1Result<()> {
        let tag = crate::asn1_tag::Asn1Tag::new(crate::asn1_tag::TagClass::Universal, Asn1Type::OctetString);
        self.write_primitive(tag, data)
    }

    /// Write an ASN.1 BIT STRING (UNIVERSAL 0x03).
    /// `unused_bits` must be 0..=7.
    pub fn write_bit_string(&mut self, data: &[u8], unused_bits: u8) -> Asn1Result<()> {
        if unused_bits > 7 {
            return Err(Asn1Error::EncodingError("Invalid unused bit count (must be 0..7)".to_string()));
        }
        let mut value = Vec::with_capacity(1 + data.len());
        value.push(unused_bits);
        value.extend_from_slice(data);
        let tag = crate::asn1_tag::Asn1Tag::new(crate::asn1_tag::TagClass::Universal, Asn1Type::BitString);
        self.write_primitive(tag, &value)
    }

    /// Write an ASN.1 UTF8String (UNIVERSAL 0x0C).
    pub fn write_utf8_string(&mut self, s: &str) -> Asn1Result<()> {
        let tag = crate::asn1_tag::Asn1Tag::new(crate::asn1_tag::TagClass::Universal, Asn1Type::Utf8String);
        self.write_primitive(tag, s.as_bytes())
    }

    /// Write an ASN.1 BOOLEAN (UNIVERSAL 0x01).
    pub fn write_boolean(&mut self, b: bool) -> Asn1Result<()> {
        let tag = crate::asn1_tag::Asn1Tag::new(crate::asn1_tag::TagClass::Universal, Asn1Type::Boolean);
        let v = if b { [0xFF] } else { [0x00] };
        self.write_primitive(tag, &v)
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
    encoder.write_boolean(value)
}

/// Write an ASN.1 integer.
pub fn write_int(encoder: &mut Asn1Encoder, value: i32) -> Asn1Result<()> {
    encoder.write_int(value)
}

/// Write an ASN.1 bit string.
pub fn write_bit_string(
    encoder: &mut Asn1Encoder,
    value: &[u8],
    unused_bits: u8
) -> Asn1Result<()> {
    encoder.write_bit_string(value, unused_bits)
}

/// Write an ASN.1 octet string.
pub fn write_octet_string(encoder: &mut Asn1Encoder, value: &[u8]) -> Asn1Result<()> {
    encoder.write_octet_string(value)
}

/// Write an ASN.1 UTF8 string.
pub fn write_utf8_string(encoder: &mut Asn1Encoder, value: &str) -> Asn1Result<()> {
    encoder.write_utf8_string(value)
}




#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1_decoder::{Asn1Decoder, read_boolean, read_octet_string, read_utf8_string};

    #[test]
    fn test_write_boolean() {
        let mut encoder = Asn1Encoder::new();

        // Encode true
        let data = encoder.write(|encoder| encoder.write_boolean(true)).unwrap();

        // Verify encoding
        assert_eq!(data, [0x01, 0x01, 0xFF]);

        // Decode and verify value
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        let result = read_boolean(&mut decoder).unwrap();
        assert_eq!(result, true);

        // Encode false
        let data = encoder.write(|encoder| encoder.write_boolean(false)).unwrap();

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
        let inner_tag = Asn1Type::OctetString as u8;
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

    #[test]
    fn test_public_encode_scope() {
        // Builds [APPLICATION|CONSTRUCTED 28] empty content
        let bytes = super::encode(|w| {
            w.write_tagged_object(28, 0x40 | 0x20, |_inner| Ok(()))
        }).unwrap();
        // Outer tag
        assert_eq!(bytes[0], (28u8 | (0x40 | 0x20)));
        // Empty length
        assert_eq!(bytes[1], 0x00);
    }
}