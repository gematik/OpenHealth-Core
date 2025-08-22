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

use std::fmt::Debug;
use std::str;
use thiserror::Error;
use crate::Asn1Tag;
use crate::asn1_date_time::{Asn1GeneralizedTime, Asn1UtcTime};
use crate::asn1_tag::asn1_type;

/// Error type for ASN.1 decoder.
#[derive(Error, Debug)]
pub enum Asn1DecoderError {
    #[error("{0}")]
    Message(String),

    #[error("{0}: {1}")]
    WithCause(String, Box<dyn std::error::Error + Send + Sync>),
}

impl Asn1DecoderError {
    pub fn new<S: Into<String>>(message: S) -> Self {
        Asn1DecoderError::Message(message.into())
    }

    pub fn with_cause<S, E>(message: S, cause: E) -> Self
    where
        S: Into<String>,
        E: std::error::Error + Send + Sync + 'static,
    {
        Asn1DecoderError::WithCause(message.into(), Box::new(cause))
    }
}

/// ASN.1 decoder for decoding data in ASN.1 format.
pub struct Asn1Decoder<'a> {
    data: &'a [u8],
    offset: usize,
    end_offset: usize,
}

impl<'a> Asn1Decoder<'a> {
    /// Creates a new ASN.1 decoder from the given data.
    pub fn new(data: &'a [u8]) -> Result<Self, Asn1DecoderError> {
        if data.is_empty() {
            return Err(Asn1DecoderError::new("Data must not be empty"));
        }
        Ok(Asn1Decoder {
            data,
            offset: 0,
            end_offset: data.len()
        })
    }

    /// Returns the current offset.
    pub fn get_offset(&self) -> usize {
        self.offset
    }

    /// Sets the current offset.
    pub fn set_offset(&mut self, value: usize) -> Result<(), Asn1DecoderError> {
        if value > self.end_offset {
            return Err(Asn1DecoderError::new("Offset must be <= `endOffset`"));
        }
        self.offset = value;
        Ok(())
    }

    /// Returns the end offset.
    pub fn get_end_offset(&self) -> usize {
        self.end_offset
    }

    /// Sets the end offset.
    pub fn set_end_offset(&mut self, value: usize) -> Result<(), Asn1DecoderError> {
        if value < self.offset {
            return Err(Asn1DecoderError::new("End offset must be >= `offset`"));
        }
        self.end_offset = value;
        Ok(())
    }

    /// Returns the remaining length.
    pub fn remaining_length(&self) -> usize {
        self.end_offset - self.offset
    }

    /// Throws an error with the given message.
    pub fn fail<S: Into<String>, T>(&self, message: S) -> Result<T, Asn1DecoderError> {
        Err(Asn1DecoderError::new(message))
    }

    /// Throws an error with the given message and cause.
    pub fn fail_with_cause<S, E, T>(&self, cause: E, message: S) -> Result<T, Asn1DecoderError>
    where
        S: Into<String>,
        E: std::error::Error + Send + Sync + 'static,
    {
        Err(Asn1DecoderError::with_cause(message, cause))
    }

    /// Checks a condition and throws an error if it's false.
    pub fn check<S: Into<String>>(&self, value: bool, message: S) -> Result<(), Asn1DecoderError> {
        if !value {
            return Err(Asn1DecoderError::new(message));
        }
        Ok(())
    }

    /// Advance with one of the blocks and return the resulting value.
    pub fn advance<T, F>(&mut self, blocks: &[F]) -> Result<T, Asn1DecoderError>
    where
        F: Fn(&mut Asn1Decoder<'a>) -> Result<T, Asn1DecoderError>,
    {
        let original_offset = self.offset;
        let original_end_offset = self.end_offset;

        for block in blocks {
            match block(self) {
                Ok(result) => return Ok(result),
                Err(_) => {
                    // Reset offsets and try next block
                    self.offset = original_offset;
                    self.end_offset = original_end_offset;
                }
            }
        }

        self.fail("No block matched")
    }

    /// Optional parsing block. Returns None if block throws an error.
    pub fn optional<T, F>(&mut self, block: F) -> Result<Option<T>, Asn1DecoderError>
    where
        F: FnOnce(&mut Asn1Decoder<'a>) -> Result<T, Asn1DecoderError>,
    {
        let original_offset = self.offset;
        let original_end_offset = self.end_offset;

        match block(self) {
            Ok(result) => Ok(Some(result)),
            Err(_) => {
                // Reset offsets
                self.offset = original_offset;
                self.end_offset = original_end_offset;
                Ok(None)
            }
        }
    }

    /// Advances the decoder with the given tag and executes the provided block.
    pub fn advance_with_tag<T, F>(&mut self, tag_number: u8, tag_class: u8, block: F) -> Result<T, Asn1DecoderError>
    where
        F: FnOnce(&mut Asn1Decoder<'a>) -> Result<T, Asn1DecoderError>,
    {
        let tag = self.read_tag()?;

        if tag.tag_number != tag_number || tag.tag_class != tag_class {
            return self.fail(format!(
                "Expected tag `{}` but got `{}`",
                Asn1Tag::new(tag_class, tag_number),
                tag
            ));
        }

        let length = self.read_length()?;
        let is_infinite_length = length == -1;

        let original_end_offset = self.end_offset;

        if is_infinite_length {
            self.end_offset = usize::MAX;
        } else {
            self.end_offset = self.offset + length as usize;
        }

        let result = block(self)?;

        match is_infinite_length {
            false => {
                if self.end_offset != self.offset {
                    return self.fail("Unparsed bytes remaining");
                }
            },
            true => {
                if self.offset + 2 <= self.data.len()
                    && self.data[self.offset] == 0x00
                    && self.data[self.offset + 1] == 0x00
                {
                    self.offset += 2; // EOC konsumieren
                } else {
                    return self.fail("Unparsed bytes remaining");
                }
            }
        }

        self.end_offset = original_end_offset;

        Ok(result)
    }

    /// Read one byte.
    pub fn read_byte(&mut self) -> Result<u8, Asn1DecoderError> {
        if self.offset >= self.end_offset {
            return self.fail("End of data reached");
        }

        let byte = self.data[self.offset];
        self.offset += 1;

        Ok(byte)
    }

    /// Read length bytes.
    pub fn read_bytes(&mut self, length: usize) -> Result<Vec<u8>, Asn1DecoderError> {
        if self.offset + length > self.end_offset {
            return self.fail("Not enough data to read requested bytes");
        }

        let bytes = self.data[self.offset..self.offset + length].to_vec();
        self.offset += length;

        Ok(bytes)
    }

    /// Reads the next tag from the data, handling multi-byte tags.
    pub fn read_tag(&mut self) -> Result<Asn1Tag, Asn1DecoderError> {
        // Read the first byte of the tag
        let first_byte = self.read_byte()?;
        let tag_class_and_constructed = (first_byte & 0xE0) as u8; // Class and constructed bits
        let tag_number = first_byte & 0x1F;

        if tag_number == 0x1F {
            // Multibyte tag: Read until MSB is 0
            let mut value: u8 = 0;
            loop {
                if self.offset >= self.end_offset {
                    return self.fail("Unexpected end of data in tag");
                }

                let next_byte = self.read_byte()?;
                value = (value << 7) | (next_byte & 0x7F);

                if next_byte & 0x80 == 0 {
                    break;
                }
            }

            Ok(Asn1Tag::new(tag_class_and_constructed, value))
        } else {
            // Single-byte tag
            Ok(Asn1Tag::new(tag_class_and_constructed, tag_number))
        }
    }

    /// Read the length. Returns `-1` for infinite length.
    pub fn read_length(&mut self) -> Result<i32, Asn1DecoderError> {
        let length_byte = self.read_byte()? as i32;

        match length_byte {
            0x80 => Ok(-1), // Infinite length
            l if l & 0x80 == 0 => Ok(l), // Short form length
            _ => {
                // Long form length
                let length_size = length_byte & 0x7F;
                self.read_int(length_size as usize, false)
            }
        }
    }

    /// Read length bytes as an integer.
    pub fn read_int(&mut self, length: usize, signed: bool) -> Result<i32, Asn1DecoderError> {
        self.check(length >= 1 && length <= 4, format!("Length must be in range of [1, 4]. Is `{}`", length))?;

        let bytes = self.read_bytes(length)?;

        let mut result = bytes[0] as i32;

        if signed && (result & 0x80) != 0 {
            // Sign extend for negative numbers
            result |= -0x100;
        } else {
            // Clear the sign bit
            result &= 0xFF;
        }

        for i in 1..length {
            result = (result << 8) | (bytes[i] as i32 & 0xFF);
        }

        Ok(result)
    }

    /// Skip length bytes.
    pub fn skip(&mut self, length: usize) -> Result<(), Asn1DecoderError> {
        if self.offset + length > self.end_offset {
            return self.fail("Cannot skip beyond end offset");
        }

        self.offset += length;
        Ok(())
    }

    /// Skip to the end offset.
    pub fn skip_to_end(&mut self) -> Result<(), Asn1DecoderError> {
        if self.end_offset == usize::MAX {
            return self.fail("Can't skip bytes inside infinite length object");
        }

        self.offset = self.end_offset;
        Ok(())
    }

    /// Reads the data using the provided block and returns the result.
    pub fn read<T, F>(&mut self, block: F) -> Result<T, Asn1DecoderError>
    where
        F: FnOnce(&mut Asn1Decoder) -> Result<T, Asn1DecoderError>,
    {
        block(self)
    }
}

/// Read ASN.1 BOOLEAN.
pub fn read_boolean(decoder: &mut Asn1Decoder) -> Result<bool, Asn1DecoderError> {
    decoder.advance_with_tag(asn1_type::BOOLEAN, 0, |decoder| {
        let byte = decoder.read_byte()?;
        Ok(byte == 0xFF)
    })
}

/// Read ASN.1 INTEGER.
pub fn read_int(decoder: &mut Asn1Decoder) -> Result<i32, Asn1DecoderError> {
    decoder.advance_with_tag(asn1_type::INTEGER, 0, |decoder| {
        decoder.read_int(decoder.remaining_length(), true)
    })
}

/// Read ASN.1 BIT_STRING.
pub fn read_bit_string(decoder: &mut Asn1Decoder) -> Result<Vec<u8>, Asn1DecoderError> {
    decoder.advance_with_tag(asn1_type::BIT_STRING, 0, |decoder| {
        let unused_bits = decoder.read_byte()? as u32;

        if unused_bits > 7 {
            return decoder.fail(format!("Invalid unused bit count: {}", unused_bits));
        }

        let mut bit_string = decoder.read_bytes(decoder.remaining_length())?;

        if unused_bits == 0 {
            Ok(bit_string)
        } else {
            if !bit_string.is_empty() {
                let last_idx = bit_string.len() - 1;
                let mask = (0xFF << unused_bits) as u8;
                bit_string[last_idx] &= mask;
            }
            Ok(bit_string)
        }
    })
}

/// Read ASN.1 UTF8_STRING.
pub fn read_utf8_string(decoder: &mut Asn1Decoder) -> Result<String, Asn1DecoderError> {
    decoder.advance_with_tag(asn1_type::UTF8_STRING, 0, |decoder| {
        let bytes = decoder.read_bytes(decoder.remaining_length())?;

        match str::from_utf8(&bytes) {
            Ok(s) => Ok(s.to_string()),
            Err(e) => decoder.fail_with_cause(e, "Malformed UTF-8 string"),
        }
    })
}

/// Read ASN.1 VISIBLE_STRING.
pub fn read_visible_string(decoder: &mut Asn1Decoder) -> Result<String, Asn1DecoderError> {
    decoder.advance_with_tag(asn1_type::VISIBLE_STRING, 0, |decoder| {
        let bytes = decoder.read_bytes(decoder.remaining_length())?;

        match str::from_utf8(&bytes) {
            Ok(s) => Ok(s.to_string()),
            Err(e) => decoder.fail_with_cause(e, "Malformed UTF-8 string"),
        }
    })
}

/// Read ASN.1 OCTET_STRING.
pub fn read_octet_string(decoder: &mut Asn1Decoder) -> Result<Vec<u8>, Asn1DecoderError> {
    decoder.advance_with_tag(asn1_type::OCTET_STRING, 0, |decoder| {
        decoder.read_bytes(decoder.remaining_length())
    })
}

/// Read ASN.1 UTC_TIME.
pub fn read_utc_time(decoder: &mut Asn1Decoder) -> Result<Asn1UtcTime, Asn1DecoderError> {
    decoder.advance_with_tag(asn1_type::UTC_TIME, 0, |decoder| {
        let bytes = decoder.read_bytes(decoder.remaining_length())?;
        let s = match str::from_utf8(&bytes) {
            Ok(s) => s,
            Err(e) => return decoder.fail_with_cause(e, "Malformed UTCTime"),
        };
        match Asn1UtcTime::parse(s) {
            Ok(t) => Ok(t),
            Err(e) => decoder.fail(format!("Malformed UTCTime: {}", e)),
        }
    })
}

/// Read ASN.1 GENERALIZED_TIME.
pub fn read_generalized_time(decoder: &mut Asn1Decoder) -> Result<Asn1GeneralizedTime, Asn1DecoderError> {
    decoder.advance_with_tag(asn1_type::GENERALIZED_TIME, 0, |decoder| {
        let bytes = decoder.read_bytes(decoder.remaining_length())?;
        let s = match str::from_utf8(&bytes) {
            Ok(s) => s,
            Err(e) => return decoder.fail_with_cause(e, "Malformed GeneralizedTime"),
        };
        match Asn1GeneralizedTime::parse(s) {
            Ok(t) => Ok(t),
            Err(e) => decoder.fail(format!("Malformed GeneralizedTime: {}", e)),
        }
    })
}

#[cfg(test)]
mod tests {
    use crate::tag_class;
    use super::*;

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .filter(|p| !p.is_empty())
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect()
    }

    #[test]
    fn test_advance_with_tag_constructed_sequence() {
        let data = hex_to_bytes("30 0A 04 03 66 6F 6F 04 03 62 61 72");
        let mut decoder = Asn1Decoder::new(&data).unwrap();

        let result = decoder.read(|d| {
            d.advance_with_tag(asn1_type::SEQUENCE, tag_class::CONSTRUCTED, |d| {
                let mut out = Vec::new();
                d.advance_with_tag(asn1_type::OCTET_STRING, 0, |d| {
                    let v = d.read_bytes(3)?;
                    out.push(String::from_utf8(v).unwrap());
                    Ok(())
                })?;
                d.advance_with_tag(asn1_type::OCTET_STRING, 0, |d| {
                    let v = d.read_bytes(3)?;
                    out.push(String::from_utf8(v).unwrap());
                    Ok(())
                })?;
                Ok(out)
            })
        }).unwrap();

        assert_eq!(result, vec!["foo".to_string(), "bar".to_string()]);
    }

    #[test]
    fn test_advance_with_tag_infinite_length() {
        let data = hex_to_bytes("30 80 04 03 66 6F 6F 04 03 62 61 72 00 00");
        let mut decoder = Asn1Decoder::new(&data).unwrap();

        let result = decoder.read(|d| {
            d.advance_with_tag(asn1_type::SEQUENCE, tag_class::CONSTRUCTED, |d| {
                let mut out = Vec::new();
                d.advance_with_tag(asn1_type::OCTET_STRING, 0, |d| {
                    let v = d.read_bytes(3)?;
                    out.push(String::from_utf8(v).unwrap());
                    Ok(())
                })?;
                d.advance_with_tag(asn1_type::OCTET_STRING, 0, |d| {
                    let v = d.read_bytes(3)?;
                    out.push(String::from_utf8(v).unwrap());
                    Ok(())
                })?;
                Ok(out)
            })
        }).unwrap();

        assert_eq!(result, vec!["foo".to_string(), "bar".to_string()]);
    }

    #[test]
    fn test_advance_with_tag_unfinished_parsing_fails() {
        let data = hex_to_bytes("30 80 04 03 66 6F 6F 04 03 62 61 72 00 00");
        let mut decoder = Asn1Decoder::new(&data).unwrap();

        let err = decoder.read(|d| {
            d.advance_with_tag(asn1_type::SEQUENCE, tag_class::CONSTRUCTED, |d| {
                d.advance_with_tag(asn1_type::OCTET_STRING, 0, |d| {
                    let _ = d.read_bytes(3)?;
                    Ok(())
                })
            })
        }).err().expect("expected error");
        match err {
            Asn1DecoderError::Message(m) => assert!(m.contains("Unparsed bytes"), "unexpected: {}", m),
            _ => panic!("unexpected error type"),
        }
    }

    #[test]
    fn test_advance_with_tag_skip_infinite_fails() {
        let data = hex_to_bytes("30 80 04 03 66 6F 6F 04 03 62 61 72 00 00");
        let mut decoder = Asn1Decoder::new(&data).unwrap();

        let err = decoder.read(|d| {
            d.advance_with_tag(asn1_type::SEQUENCE, tag_class::CONSTRUCTED, |d| {
                d.advance_with_tag(asn1_type::OCTET_STRING, 0, |d| {
                    let _ = d.read_bytes(3)?;
                    Ok(())
                })?;
                d.skip_to_end()
            })
        }).err().expect("expected error");
        match err {
            Asn1DecoderError::Message(m) => assert!(m.contains("Can't skip bytes inside infinite length object"), "unexpected: {}", m),
            _ => panic!("unexpected error type"),
        }
    }

    #[test]
    fn test_read_boolean_true_false() {
        // true
        let data = hex_to_bytes("01 01 FF");
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        assert!(read_boolean(&mut decoder).unwrap());

        // false
        let data = hex_to_bytes("01 01 00");
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        assert!(!read_boolean(&mut decoder).unwrap());
    }

    #[test]
    fn test_read_integer_cases() {
        // 127
        let data = hex_to_bytes("02 01 7F");
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        assert_eq!(read_int(&mut decoder).unwrap(), 127);

        // -20 (0xEC)
        let data = hex_to_bytes("02 01 EC");
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        assert_eq!(read_int(&mut decoder).unwrap(), -20);

        // -128 (0x80)
        let data = hex_to_bytes("02 01 80");
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        assert_eq!(read_int(&mut decoder).unwrap(), -128);

        // 0x7F7F = 32639
        let data = hex_to_bytes("02 02 7F 7F");
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        assert_eq!(read_int(&mut decoder).unwrap(), 32639);

        // 0x0100 = 256
        let data = hex_to_bytes("02 02 01 00");
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        assert_eq!(read_int(&mut decoder).unwrap(), 256);
    }

    #[test]
    fn test_read_bit_string_cases() {
        // No unused bits
        let data = hex_to_bytes("03 05 00 FF AA BB CC");
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        let v = read_bit_string(&mut decoder).unwrap();
        assert_eq!(v, hex_to_bytes("FF AA BB CC"));

        // Last 3 bits unused -> mask last byte (0xFF -> 0xF8)
        let data = hex_to_bytes("03 05 03 FF AA BB FF");
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        let v = read_bit_string(&mut decoder).unwrap();
        assert_eq!(v, hex_to_bytes("FF AA BB F8"));

        // Empty bit string (just unused bits byte 0)
        let data = hex_to_bytes("03 01 00");
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        let v = read_bit_string(&mut decoder).unwrap();
        assert_eq!(v.len(), 0);

        // Invalid unused bits > 7
        let data = hex_to_bytes("03 04 08 FF AA BB CC");
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        assert!(read_bit_string(&mut decoder).is_err());

        // Within complex structure
        let data = hex_to_bytes("30 0C 03 04 00 FF AA BB 03 04 01 CC DD 00");
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        let result = decoder.read(|d| {
            d.advance_with_tag(asn1_type::SEQUENCE, tag_class::CONSTRUCTED, |d| {
                let first = read_bit_string(d)?;
                let second = read_bit_string(d)?;
                Ok(vec![first, second])
            })
        }).unwrap();
        assert_eq!(result[0], hex_to_bytes("FF AA BB"));
        assert_eq!(result[1], hex_to_bytes("CC DD 00"));
    }

    #[test]
    fn test_read_utf8_and_visible_strings() {
        // UTF8 "Hello"
        let data = hex_to_bytes("0C 05 48 65 6C 6C 6F");
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        assert_eq!(read_utf8_string(&mut decoder).unwrap(), "Hello");

        // UTF8 empty
        let data = hex_to_bytes("0C 00");
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        assert_eq!(read_utf8_string(&mut decoder).unwrap(), "");

        // UTF8 invalid bytes
        let data = hex_to_bytes("0C 02 C3 28");
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        assert!(read_utf8_string(&mut decoder).is_err());

        // Visible "World"
        let data = hex_to_bytes("1A 05 57 6F 72 6C 64");
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        assert_eq!(read_visible_string(&mut decoder).unwrap(), "World");

        // Visible with ASCII space/symbols "AB !@#"
        let data = hex_to_bytes("1A 06 41 42 20 21 40 23");
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        assert_eq!(read_visible_string(&mut decoder).unwrap(), "AB !@#");
    }

    #[test]
    fn test_read_utc_time_cases() {
        // 2023-05-12 14:39:45Z => "230512143945Z"
        let data = hex_to_bytes("17 0D 32 33 30 35 31 32 31 34 33 39 34 35 5A");
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        let t = read_utc_time(&mut decoder).unwrap();
        assert_eq!(t.year, 2023);
        assert_eq!(t.month, 5);
        assert_eq!(t.day, 12);
        assert_eq!(t.hour, 14);
        assert_eq!(t.minute, 39);
        assert_eq!(t.second, Some(45));
        assert!(t.offset.is_none());

        // with negative offset: "...-0500"
        let data = hex_to_bytes("17 11 32 33 30 35 31 32 31 34 33 39 34 35 2D 30 35 30 30");
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        let t = read_utc_time(&mut decoder).unwrap();
        assert_eq!(t.year, 2023);
        assert_eq!(t.month, 5);
        assert_eq!(t.day, 12);
        assert_eq!(t.hour, 14);
        assert_eq!(t.minute, 39);
        assert_eq!(t.second, Some(45));
        if let Some(off) = t.offset {
            assert_eq!(off.hours, -5);
            assert_eq!(off.minutes, 0);
        } else {
            panic!("expected offset");
        }

        // missing seconds: "2305121439Z"
        let data = hex_to_bytes("17 0B 32 33 30 35 31 32 31 34 33 39 5A");
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        let t = read_utc_time(&mut decoder).unwrap();
        assert_eq!(t.year, 2023);
        assert_eq!(t.month, 5);
        assert_eq!(t.day, 12);
        assert_eq!(t.hour, 14);
        assert_eq!(t.minute, 39);
        assert_eq!(t.second, None);
        assert!(t.offset.is_none());
    }

    #[test]
    fn test_read_generalized_time_cases() {
        // "20230512143945.123Z"
        let data = hex_to_bytes("18 12 32 30 32 33 30 35 31 32 31 34 33 39 34 35 2E 31 32 33 5A");
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        let t = read_generalized_time(&mut decoder).unwrap();
        assert_eq!(t.year, 2023);
        assert_eq!(t.month, 5);
        assert_eq!(t.day, 12);
        assert_eq!(t.hour, 14);
        assert_eq!(t.minute, Some(39));
        assert_eq!(t.second, Some(45));
        assert_eq!(t.fraction_of_second, Some(123));
        assert!(t.offset.is_none());

        // "202305121439Z" (no seconds)
        let data = hex_to_bytes("18 0D 32 30 32 33 30 35 31 32 31 34 33 39 5A");
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        let t = read_generalized_time(&mut decoder).unwrap();
        assert_eq!(t.year, 2023);
        assert_eq!(t.month, 5);
        assert_eq!(t.day, 12);
        assert_eq!(t.hour, 14);
        assert_eq!(t.minute, Some(39));
        assert_eq!(t.second, None);
        assert_eq!(t.fraction_of_second, None);
        assert!(t.offset.is_none());
    }
}