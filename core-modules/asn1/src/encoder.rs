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

use crate::error::{EncoderError, EncoderResult};
use crate::tag::{Asn1Class, Asn1Form, Asn1Id, UniversalTag};

pub type Result<T> = EncoderResult<T>;

/// ASN.1 encoder for encoding data in ASN.1 format.
pub struct Asn1Encoder;

/// Scope for writing ASN.1 encoded data. (Top-level, not nested)
pub struct WriterScope {
    // TODO: support zeroizing vec
    buffer: Vec<u8>,
}

impl WriterScope {
    pub fn new() -> Self {
        Self { buffer: Vec::new() }
    }

    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    /// Appends a byte to the buffer.
    #[inline]
    pub fn write_byte(&mut self, byte: u8) {
        self.buffer.push(byte);
    }

    /// Appends a byte array to the buffer.
    #[inline]
    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.buffer.extend_from_slice(bytes);
    }

    /// Writes an integer in big-endian format, using a variable-length encoding.
    pub fn write_int(&mut self, integer: i32) {
        let mut bytes: Vec<u8> = Vec::new();
        let mut value = integer;
        while value < -0x80 || value >= 0x80 {
            bytes.push((value & 0xFF) as u8);
            value /= 0x100;
        }
        bytes.push((value & 0xFF) as u8);
        // big endian ausgeben
        for b in bytes.iter().rev() {
            self.write_byte(*b);
        }
    }

    /// Writes a length in a variable-length encoding.
    pub fn write_length(&mut self, length: u64) {
        if length < 0x80 {
            // Single byte length
            self.write_byte(length as u8);
        } else {
            // Multibyte length
            let mut length_bytes: Vec<u8> = Vec::new();
            let mut value = length;
            while value != 0 {
                length_bytes.push((value & 0xFF) as u8);
                value >>= 8;
            }
            // length-of-length
            self.write_byte(0x80 | (length_bytes.len() as u8));
            for b in length_bytes.iter().rev() {
                self.write_byte(*b);
            }
        }
    }

    /// Writes the length of the buffer in a variable-length encoding
    /// and then the buffer itself.
    pub fn write_scope(&mut self, other: &WriterScope) {
        // length
        self.write_length(other.buffer.len() as u64);
        // value
        self.write_bytes(&other.buffer);
    }

    /// Write the encoded tag directly, handling multi-byte encoding for large tags.
    fn write_tag(&mut self, number: u32, class: Asn1Class, form: Asn1Form) {
        let first = (class as u8) | (form as u8);

        if number < 31 {
            // Short form - encoded in one byte
            self.write_byte(first | (number as u8));
        } else {
            // Long form - first byte indicates extended tag number
            self.write_byte(first | 0x1F);

            // Encode tag number in base-128, big-endian, MSB=1 except last
            let mut buf = [0u8; 5]; // enough for 32-bit
            let mut i = buf.len();
            let mut n = number;
            while n > 0 {
                buf[i - 1] = (n as u8) & 0x7F;
                n >>= 7;
                i -= 1;
            }
            for (j, b) in buf[i..].iter().enumerate() {
                let last = j == (buf.len() - i - 1);
                self.write_byte(if last { *b } else { *b | 0x80 });
            }
        }
    }

    /// Write an ASN.1 tagged object.
    pub fn write_tagged_object(
        &mut self,
        id: Asn1Id,
        block: impl FnOnce(&mut WriterScope) -> Result<()>,
    ) -> Result<()> {
        // tag
        self.write_tag(id.number, id.class, id.form);
        // scope
        let mut scope = WriterScope::new();
        block(&mut scope)?;
        // length + value
        self.write_scope(&scope);
        Ok(())
    }

    /// Write an ASN.1 integer.
    pub fn write_asn1_int(&mut self, value: i32) -> Result<()> {
        self.write_tagged_object(UniversalTag::Integer.primitive(), |s| {
            s.write_int(value);
            Ok(())
        })
    }

    /// Write an ASN.1 boolean.
    pub fn write_asn1_boolean(&mut self, value: bool) -> Result<()> {
        self.write_tagged_object(UniversalTag::Boolean.primitive(), |s| {
            s.write_byte(if value { 0xFF } else { 0x00 });
            Ok(())
        })
    }

    /// Write an ASN.1 bit string.
    pub fn write_asn1_bit_string(&mut self, value: &[u8], unused_bits: u8) -> Result<()> {
        if !(0..=7).contains(&unused_bits) {
            return Err(EncoderError::new(format!("Invalid unused bit count: {}", unused_bits)));
        }
        self.write_tagged_object(UniversalTag::BitString.primitive(), |s| {
            s.write_byte(unused_bits);
            s.write_bytes(value);
            Ok(())
        })
    }

    /// Write an ASN.1 octet string.
    pub fn write_asn1_octet_string(&mut self, value: &[u8]) -> Result<()> {
        self.write_tagged_object(UniversalTag::OctetString.primitive(), |s| {
            s.write_bytes(value);
            Ok(())
        })
    }

    /// Write an ASN.1 utf8 string.
    pub fn write_asn1_utf8_string(&mut self, value: &str) -> Result<()> {
        self.write_tagged_object(UniversalTag::Utf8String.primitive(), |s| {
            s.write_bytes(value.as_bytes());
            Ok(())
        })
    }

    /// Write [Asn1Type.OBJECT_IDENTIFIER].
    pub fn write_object_identifier(&mut self, oid: &str) -> Result<()> {
        self.write_tagged_object(UniversalTag::ObjectIdentifier.primitive(), |s| {
            let parts: Vec<i32> = oid
                .split('.')
                .map(|p| p.parse::<i32>().map_err(|_| EncoderError::new(format!("Invalid OID part: {}", p))))
                .collect::<std::result::Result<_, _>>()?;

            if parts.len() < 2 {
                return Err(EncoderError::new("OID must have at least two components"));
            }

            let first = parts[0];
            let second = parts[1];

            if !(0..=2).contains(&first) {
                return Err(EncoderError::new("OID first part must be 0, 1, or 2"));
            }
            if first < 2 && !(0..=39).contains(&second) {
                return Err(EncoderError::new("OID second part must be 0-39 for first part 0 or 1"));
            }

            let first_byte = first * 40 + second;
            s.write_multi_byte(first_byte);

            for part in parts.iter().skip(2) {
                s.write_multi_byte(*part);
            }
            Ok(())
        })
    }

    fn write_multi_byte(&mut self, mut integer: i32) {
        let mut bytes: Vec<u8> = Vec::new();
        loop {
            bytes.push((integer & 0x7F) as u8);
            integer >>= 7;
            if integer <= 0 {
                break;
            }
        }
        for (i, b) in bytes.iter().rev().enumerate() {
            if i == bytes.len() - 1 {
                self.write_byte(*b);
            } else {
                self.write_byte(*b | 0x80);
            }
        }
    }

    fn write_base128(&mut self, mut integer: i32) {
        let mut bytes: Vec<u8> = Vec::new();
        loop {
            bytes.push((integer & 0x7F) as u8);
            integer >>= 7;
            if integer <= 0 {
                break;
            }
        }
        // reverse order, MSB=1 für alle außer die letzte
        for (i, b) in bytes.iter().rev().enumerate() {
            if i == bytes.len() - 1 {
                self.write_byte(*b);
            } else {
                self.write_byte(*b | 0x80);
            }
        }
    }
}

impl Asn1Encoder {
    /// Encodes the given block of code and returns the resulting byte array.
    pub fn write(block: impl FnOnce(&mut WriterScope) -> Result<()>) -> Result<Vec<u8>> {
        let mut scope = WriterScope::new();
        block(&mut scope)?;
        Ok(scope.buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tag::TagNumberExt;

    fn hex(bytes: &[u8]) -> String {
        let mut out = String::new();
        for (i, b) in bytes.iter().enumerate() {
            if i > 0 {
                out.push(' ');
            }
            out.push_str(&format!("{:02X}", b));
        }
        out
    }

    #[test]
    fn write_multi_byte_tag_small_value() {
        let result = Asn1Encoder::write(|w| {
            w.write_tagged_object(33u8.application_tag(), |inner| {
                inner.write_byte(0x05);
                Ok(())
            })
        })
        .unwrap();
        assert_eq!(hex(&result), "5F 21 01 05");
    }

    #[test]
    fn write_multi_byte_tag_larger_value() {
        let result = Asn1Encoder::write(|w| {
            w.write_tagged_object(128u32.application_tag(), |inner| {
                inner.write_byte(0x05);
                Ok(())
            })
        })
        .unwrap();
        assert_eq!(hex(&result), "5F 81 00 01 05");
    }

    #[test]
    fn write_multi_byte_tag_max_single_byte() {
        let result = Asn1Encoder::write(|w| {
            w.write_tagged_object(30u8.application_tag(), |inner| {
                inner.write_byte(0x05);
                Ok(())
            })
        })
        .unwrap();
        assert_eq!(hex(&result), "5E 01 05");
    }

    #[test]
    fn write_multi_byte_length() {
        let result = Asn1Encoder::write(|w| {
            w.write_length(123_456_789u64);
            Ok(())
        })
        .unwrap();
        assert_eq!(hex(&result), "84 07 5B CD 15");
    }

    #[test]
    fn write_int_expected() {
        let result = Asn1Encoder::write(|w| {
            w.write_asn1_int(123_456)?;
            Ok(())
        })
        .unwrap();
        assert_eq!(hex(&result), "02 03 01 E2 40");
    }

    #[test]
    fn write_int_zero() {
        let result = Asn1Encoder::write(|w| {
            w.write_asn1_int(0)?;
            Ok(())
        })
        .unwrap();
        assert_eq!(hex(&result), "02 01 00");
    }

    #[test]
    fn write_int_negative() {
        let result = Asn1Encoder::write(|w| {
            w.write_asn1_int(-123)?;
            Ok(())
        })
        .unwrap();
        assert_eq!(hex(&result), "02 01 85");
    }

    #[test]
    fn write_utf8_string_expected() {
        let result = Asn1Encoder::write(|w| {
            w.write_asn1_utf8_string("hello")?;
            Ok(())
        })
        .unwrap();
        assert_eq!(hex(&result), "0C 05 68 65 6C 6C 6F");
    }

    #[test]
    fn write_utf8_string_empty() {
        let result = Asn1Encoder::write(|w| {
            w.write_asn1_utf8_string("")?;
            Ok(())
        })
        .unwrap();
        assert_eq!(hex(&result), "0C 00");
    }

    #[test]
    fn write_boolean_true() {
        let result = Asn1Encoder::write(|w| {
            w.write_asn1_boolean(true)?;
            Ok(())
        })
        .unwrap();
        assert_eq!(hex(&result), "01 01 FF");
    }

    #[test]
    fn write_boolean_false() {
        let result = Asn1Encoder::write(|w| {
            w.write_asn1_boolean(false)?;
            Ok(())
        })
        .unwrap();
        assert_eq!(hex(&result), "01 01 00");
    }

    #[test]
    fn write_with_nested_tags() {
        let result = Asn1Encoder::write(|w| {
            // Universal constructed SEQUENCE (0x10 with constructed bit)
            w.write_tagged_object(0x10u8.universal_tag().constructed(), |inner| {
                inner.write_asn1_int(42)?;
                inner.write_asn1_utf8_string("test")?;
                Ok(())
            })?;
            Ok(())
        })
        .unwrap();
        assert_eq!(hex(&result), "30 09 02 01 2A 0C 04 74 65 73 74");
    }

    #[test]
    fn write_oid_simple() {
        let result = Asn1Encoder::write(|w| {
            w.write_object_identifier("1.2.840.113549")?;
            Ok(())
        })
        .unwrap();
        assert_eq!(hex(&result), "06 06 2A 86 48 86 F7 0D");
    }

    #[test]
    fn write_oid_single_part_beyond_40() {
        let result = Asn1Encoder::write(|w| {
            w.write_object_identifier("2.100.3")?;
            Ok(())
        })
        .unwrap();
        assert_eq!(hex(&result), "06 03 81 34 03");
    }

    #[test]
    fn write_oid_long_identifier() {
        let result = Asn1Encoder::write(|w| {
            w.write_object_identifier("1.2.3.4.5.265566")?;
            Ok(())
        })
        .unwrap();
        assert_eq!(hex(&result), "06 07 2A 03 04 05 90 9A 5E");
    }

    #[test]
    fn write_oid_large_first_component() {
        let result = Asn1Encoder::write(|w| {
            w.write_object_identifier("2.999.1")?;
            Ok(())
        })
        .unwrap();
        assert_eq!(hex(&result), "06 03 88 37 01");
    }

    #[test]
    fn write_oid_invalid_first_part_panics() {
        let res = Asn1Encoder::write(|w| {
            w.write_object_identifier("3.1.2")?;
            Ok(())
        });
        assert!(res.is_err());
    }

    #[test]
    fn write_oid_invalid_encoding_panics() {
        let res = Asn1Encoder::write(|w| {
            w.write_object_identifier("1.40.1")?;
            Ok(())
        });
        assert!(res.is_err());
    }
}
