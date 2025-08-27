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
use crate::asn1_date_time::{Asn1GeneralizedTime, Asn1UtcTime};
use crate::asn1_tag::{Asn1Type, TagClass};
use crate::Asn1Tag;
use crate::error::{Asn1Error, Result as Asn1Result};

/// ASN.1 decoder for decoding data in ASN.1 format.
pub struct Asn1Decoder<'a> {
    data: &'a [u8],
    offset: usize,
    end_offset: usize,
}

impl<'a> Asn1Decoder<'a> {
    /// Creates a new ASN.1 decoder from the given data.
    pub fn new(data: &'a [u8]) -> Asn1Result<Self> {
        if data.is_empty() {
            return Err(Asn1Error::DecodingError("Data must not be empty".to_string()));
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
    pub fn set_offset(&mut self, value: usize) -> Asn1Result<()> {
        if value > self.end_offset {
            return Err(Asn1Error::DecodingError("Offset must be <= `endOffset`".to_string()));
        }
        self.offset = value;
        Ok(())
    }

    /// Returns the end offset.
    pub fn get_end_offset(&self) -> usize {
        self.end_offset
    }

    /// Sets the end offset.
    pub fn set_end_offset(&mut self, value: usize) -> Asn1Result<()> {
        if value < self.offset {
            return Err(Asn1Error::DecodingError("End offset must be >= `offset`".to_string()));
        }
        self.end_offset = value;
        Ok(())
    }

    /// Returns the remaining length.
    pub fn remaining_length(&self) -> usize {
        self.end_offset - self.offset
    }

    /// Throws an error with the given message.
    pub fn fail<S: Into<String>, T>(&self, message: S) -> Asn1Result<T> {
        Err(Asn1Error::DecodingError(message.into()))
    }

    /// Throws an error with the given message and cause.
    pub fn fail_with_cause<S, E, T>(&self, cause: E, message: S) -> Asn1Result<T>
    where
        S: Into<String>,
        E: std::error::Error + Send + Sync + 'static,
    {
        Err(Asn1Error::DecodingError(format!("{}: {}", message.into(), cause)))
    }

    /// Checks a condition and throws an error if it's false.
    pub fn check<S: Into<String>>(&self, value: bool, message: S) -> Asn1Result<()> {
        if !value {
            return Err(Asn1Error::DecodingError(message.into()));
        }
        Ok(())
    }

    /// Advance with one of the blocks and return the resulting value.
    pub fn advance<T, F>(&mut self, blocks: &[F]) -> Asn1Result<T>
    where
        F: Fn(&mut Asn1Decoder<'a>) -> Asn1Result<T>,
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
    pub fn optional<T, F>(&mut self, block: F) -> Asn1Result<Option<T>>
    where
        F: FnOnce(&mut Asn1Decoder<'a>) -> Asn1Result<T>,
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

    /// Advances the decoder with the given expected tag and executes the provided block.
    pub fn advance_with_tag<T, F>(&mut self, expected: Asn1Tag, block: F) -> Asn1Result<T>
    where
        F: FnOnce(&mut Asn1Decoder<'a>) -> Asn1Result<T>,
    {
        let actual = self.read_tag()?;

        if actual.class != expected.class || actual.constructed != expected.constructed || actual.asn1_type != expected.asn1_type {
            return self.fail(format!(
                "Expected tag `{}` but got `{}`",
                expected,
                actual
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
    pub fn read_byte(&mut self) -> Asn1Result<u8> {
        if self.offset >= self.end_offset {
            return self.fail("End of data reached");
        }

        let byte = self.data[self.offset];
        self.offset += 1;

        Ok(byte)
    }

    /// Read length bytes.
    pub fn read_bytes(&mut self, length: usize) -> Asn1Result<Vec<u8>> {
        if self.offset + length > self.end_offset {
            return self.fail("Not enough data to read requested bytes");
        }

        let bytes = self.data[self.offset..self.offset + length].to_vec();
        self.offset += length;

        Ok(bytes)
    }

    /// Reads the next tag from the data, handling multi-byte tags.
    pub fn read_tag(&mut self) -> Asn1Result<Asn1Tag> {
        let first_byte = self.read_byte()?;
        let class_bits = first_byte & 0xC0;
        let constructed = (first_byte & 0x20) != 0;
        let tag_number_low = first_byte & 0x1F;

        let class = match class_bits {
            0x00 => TagClass::Universal,
            0x40 => TagClass::Application,
            0x80 => TagClass::ContextSpecific,
            0xC0 => TagClass::Private,
            _ => unreachable!(),
        };

        let number: u32 = if tag_number_low == 0x1F {
            // High-tag-number form: base-128 big-endian with MSB as continuation
            let mut value: u32 = 0;
            loop {
                if self.offset >= self.end_offset { return self.fail("Unexpected end of data in tag"); }
                let b = self.read_byte()?;
                value = (value << 7) | (b & 0x7F) as u32;
                if (b & 0x80) == 0 { break; }
            }
            value
        } else {
            tag_number_low as u32
        };

        let asn1_type = Asn1Type::try_from(number as u8)
            .map_err(|raw| Asn1Error::DecodingError(format!("Unknown universal tag: 0x{:X}", raw)))?;

        Ok(Asn1Tag { class, constructed, asn1_type })
    }

    /// Read the length. Returns `-1` for infinite length.
    pub fn read_length(&mut self) -> Asn1Result<i32> {
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
    pub fn read_int(&mut self, length: usize, signed: bool) -> Asn1Result<i32> {
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
    pub fn skip(&mut self, length: usize) -> Asn1Result<()> {
        if self.offset + length > self.end_offset {
            return self.fail("Cannot skip beyond end offset");
        }

        self.offset += length;
        Ok(())
    }

    /// Skip to the end offset.
    pub fn skip_to_end(&mut self) -> Asn1Result<()> {
        if self.end_offset == usize::MAX {
            return self.fail("Can't skip bytes inside infinite length object");
        }

        self.offset = self.end_offset;
        Ok(())
    }

    /// Reads the data using the provided block and returns the result.
    pub fn read<T, F>(&mut self, block: F) -> Asn1Result<T>
    where
        F: FnOnce(&mut Asn1Decoder) -> Asn1Result<T>,
    {
        block(self)
    }
}

/// Scoped decode helper mirroring `encode(|w| ...)` on the encoder side.
pub fn decode<T, F>(data: &[u8], f: F) -> Asn1Result<T>
where
    F: FnOnce(&mut Asn1Decoder<'_>) -> Asn1Result<T>,
{
    let mut decoder = Asn1Decoder::new(data)?;
    decoder.read(f)
}

/// Read ASN.1 BOOLEAN.
pub fn read_boolean(decoder: &mut Asn1Decoder) -> Asn1Result<bool> {
    decoder.advance_with_tag(
        Asn1Tag::new(TagClass::Universal, Asn1Type::Boolean),
        |decoder| {
            let byte = decoder.read_byte()?;
            Ok(byte == 0xFF)
        }
    )
}

/// Read ASN.1 INTEGER.
pub fn read_int(decoder: &mut Asn1Decoder) -> Asn1Result<i32> {
    decoder.advance_with_tag(
        Asn1Tag::new(TagClass::Universal, Asn1Type::Integer),
        |decoder| {
            decoder.read_int(decoder.remaining_length(), true)
        }
    )
}

/// Read ASN.1 BIT_STRING.
pub fn read_bit_string(decoder: &mut Asn1Decoder) -> Asn1Result<Vec<u8>> {
    decoder.advance_with_tag(
        Asn1Tag::new(TagClass::Universal, Asn1Type::BitString),
        |decoder| {
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
        }
    )
}

/// Read ASN.1 UTF8_STRING.
pub fn read_utf8_string(decoder: &mut Asn1Decoder) -> Asn1Result<String> {
    decoder.advance_with_tag(
        Asn1Tag::new(TagClass::Universal, Asn1Type::Utf8String),
        |decoder| {
            let bytes = decoder.read_bytes(decoder.remaining_length())?;
            match str::from_utf8(&bytes) {
                Ok(s) => Ok(s.to_string()),
                Err(e) => decoder.fail_with_cause(e, "Malformed UTF-8 string"),
            }
        }
    )
}

/// Read ASN.1 VISIBLE_STRING.
pub fn read_visible_string(decoder: &mut Asn1Decoder) -> Asn1Result<String> {
    decoder.advance_with_tag(
        Asn1Tag::new(TagClass::Universal, Asn1Type::VisibleString),
        |decoder| {
            let bytes = decoder.read_bytes(decoder.remaining_length())?;
            match str::from_utf8(&bytes) {
                Ok(s) => Ok(s.to_string()),
                Err(e) => decoder.fail_with_cause(e, "Malformed UTF-8 string"),
            }
        }
    )
}

/// Read ASN.1 OCTET_STRING.
pub fn read_octet_string(decoder: &mut Asn1Decoder) -> Asn1Result<Vec<u8>> {
    decoder.advance_with_tag(
        Asn1Tag::new(TagClass::Universal, Asn1Type::OctetString),
        |decoder| decoder.read_bytes(decoder.remaining_length())
    )
}

/// Read ASN.1 UTC_TIME.
pub fn read_utc_time(decoder: &mut Asn1Decoder) -> Asn1Result<Asn1UtcTime> {
    decoder.advance_with_tag(
        Asn1Tag::new(TagClass::Universal, Asn1Type::UtcTime),
        |decoder| {
            let bytes = decoder.read_bytes(decoder.remaining_length())?;
            let s = match str::from_utf8(&bytes) {
                Ok(s) => s,
                Err(e) => return decoder.fail_with_cause(e, "Malformed UTCTime"),
            };
            match Asn1UtcTime::parse(s) {
                Ok(t) => Ok(t),
                Err(e) => decoder.fail(format!("Malformed UTCTime: {}", e)),
            }
        }
    )
}

/// Read ASN.1 GENERALIZED_TIME.
pub fn read_generalized_time(decoder: &mut Asn1Decoder) -> Asn1Result<Asn1GeneralizedTime> {
    decoder.advance_with_tag(
        Asn1Tag::new(TagClass::Universal, Asn1Type::GeneralizedTime),
        |decoder| {
            let bytes = decoder.read_bytes(decoder.remaining_length())?;
            let s = match str::from_utf8(&bytes) {
                Ok(s) => s,
                Err(e) => return decoder.fail_with_cause(e, "Malformed GeneralizedTime"),
            };
            match Asn1GeneralizedTime::parse(s) {
                Ok(t) => Ok(t),
                Err(e) => decoder.fail(format!("Malformed GeneralizedTime: {}", e)),
            }
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1_tag::{Asn1Tag, TagClass};

    fn hex_to_bytes(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .filter(|p| !p.is_empty())
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect()
    }

    #[test]
    fn test_advance_with_tag_constructed_sequence() {
        let data = hex_to_bytes("30 0A 04 03 66 6F 6F 04 03 62 61 72");
        let result = decode(&data, |d| {
            d.advance_with_tag(
                Asn1Tag::new(TagClass::Universal, Asn1Type::Sequence).with_constructed(true),
                |d| {
                    let mut out = Vec::new();
                    d.advance_with_tag(
                        Asn1Tag::new(TagClass::Universal, Asn1Type::OctetString),
                        |d| {
                            let v = d.read_bytes(3)?;
                            out.push(String::from_utf8(v).unwrap());
                            Ok(())
                        }
                    )?;
                    d.advance_with_tag(
                        Asn1Tag::new(TagClass::Universal, Asn1Type::OctetString),
                        |d| {
                            let v = d.read_bytes(3)?;
                            out.push(String::from_utf8(v).unwrap());
                            Ok(())
                        }
                    )?;
                    Ok(out)
                }
            )
        }).unwrap();

        assert_eq!(result, vec!["foo".to_string(), "bar".to_string()]);
    }

    #[test]
    fn test_advance_with_tag_infinite_length() {
        let data = hex_to_bytes("30 80 04 03 66 6F 6F 04 03 62 61 72 00 00");
        let result = decode(&data, |d| {
            d.advance_with_tag(
                Asn1Tag::new(TagClass::Universal, Asn1Type::Sequence).with_constructed(true),
                |d| {
                    let mut out = Vec::new();
                    d.advance_with_tag(
                        Asn1Tag::new(TagClass::Universal, Asn1Type::OctetString),
                        |d| {
                            let v = d.read_bytes(3)?;
                            out.push(String::from_utf8(v).unwrap());
                            Ok(())
                        }
                    )?;
                    d.advance_with_tag(
                        Asn1Tag::new(TagClass::Universal, Asn1Type::OctetString),
                        |d| {
                            let v = d.read_bytes(3)?;
                            out.push(String::from_utf8(v).unwrap());
                            Ok(())
                        }
                    )?;
                    Ok(out)
                }
            )
        }).unwrap();

        assert_eq!(result, vec!["foo".to_string(), "bar".to_string()]);
    }

    #[test]
    fn test_advance_with_tag_unfinished_parsing_fails() {
        let data = hex_to_bytes("30 80 04 03 66 6F 6F 04 03 62 61 72 00 00");
        let err = decode(&data, |d| {
            d.advance_with_tag(
                Asn1Tag::new(TagClass::Universal, Asn1Type::Sequence).with_constructed(true),
                |d| {
                    d.advance_with_tag(
                        Asn1Tag::new(TagClass::Universal, Asn1Type::OctetString),
                        |d| {
                            let _ = d.read_bytes(3)?;
                            Ok(())
                        }
                    )
                }
            )
        }).err().expect("expected error");
        assert!(err.to_string().contains("Unparsed bytes"), "unexpected: {}", err);
    }

    #[test]
    fn test_advance_with_tag_skip_infinite_fails() {
        let data = hex_to_bytes("30 80 04 03 66 6F 6F 04 03 62 61 72 00 00");
        let err = decode(&data, |d| {
            d.advance_with_tag(
                Asn1Tag::new(TagClass::Universal, Asn1Type::Sequence).with_constructed(true),
                |d| {
                    d.advance_with_tag(
                        Asn1Tag::new(TagClass::Universal, Asn1Type::OctetString),
                        |d| {
                            let _ = d.read_bytes(3)?;
                            Ok(())
                        }
                    )?;
                    d.skip_to_end()
                }
            )
        }).err().expect("expected error");
        assert!(err.to_string().contains("Can't skip bytes inside infinite length object"), "unexpected: {}", err);
    }

    #[test]
    fn test_read_boolean_true_false() {
        // true
        let data = hex_to_bytes("01 01 FF");
        assert!(decode(&data, |d| read_boolean(d)).unwrap());

        // false
        let data = hex_to_bytes("01 01 00");
        assert!(!decode(&data, |d| read_boolean(d)).unwrap());
    }

    #[test]
    fn test_read_integer_cases() {
        // 127
        let data = hex_to_bytes("02 01 7F");
        assert_eq!(decode(&data, |d| read_int(d)).unwrap(), 127);

        // -20 (0xEC)
        let data = hex_to_bytes("02 01 EC");
        assert_eq!(decode(&data, |d| read_int(d)).unwrap(), -20);

        // -128 (0x80)
        let data = hex_to_bytes("02 01 80");
        assert_eq!(decode(&data, |d| read_int(d)).unwrap(), -128);

        // 0x7F7F = 32639
        let data = hex_to_bytes("02 02 7F 7F");
        assert_eq!(decode(&data, |d| read_int(d)).unwrap(), 32639);

        // 0x0100 = 256
        let data = hex_to_bytes("02 02 01 00");
        assert_eq!(decode(&data, |d| read_int(d)).unwrap(), 256);
    }

    #[test]
    fn test_read_bit_string_cases() {
        // No unused bits
        let data = hex_to_bytes("03 05 00 FF AA BB CC");
        let v = decode(&data, |d| read_bit_string(d)).unwrap();
        assert_eq!(v, hex_to_bytes("FF AA BB CC"));

        // Last 3 bits unused -> mask last byte (0xFF -> 0xF8)
        let data = hex_to_bytes("03 05 03 FF AA BB FF");
        let v = decode(&data, |d| read_bit_string(d)).unwrap();
        assert_eq!(v, hex_to_bytes("FF AA BB F8"));

        // Empty bit string (just unused bits byte 0)
        let data = hex_to_bytes("03 01 00");
        let v = decode(&data, |d| read_bit_string(d)).unwrap();
        assert_eq!(v.len(), 0);

        // Invalid unused bits > 7
        let data = hex_to_bytes("03 04 08 FF AA BB CC");
        assert!(decode(&data, |d| read_bit_string(d)).is_err());

        // Within complex structure
        let data = hex_to_bytes("30 0C 03 04 00 FF AA BB 03 04 01 CC DD 00");
        let result = decode(&data, |d| {
            d.advance_with_tag(
                Asn1Tag::new(TagClass::Universal, Asn1Type::Sequence).with_constructed(true),
                |d| {
                    let first = read_bit_string(d)?;
                    let second = read_bit_string(d)?;
                    Ok(vec![first, second])
                }
            )
        }).unwrap();
        assert_eq!(result[0], hex_to_bytes("FF AA BB"));
        assert_eq!(result[1], hex_to_bytes("CC DD 00"));
    }

    #[test]
    fn test_read_utf8_and_visible_strings() {
        // UTF8 "Hello"
        let data = hex_to_bytes("0C 05 48 65 6C 6C 6F");
        assert_eq!(decode(&data, |d| read_utf8_string(d)).unwrap(), "Hello");

        // UTF8 empty
        let data = hex_to_bytes("0C 00");
        assert_eq!(decode(&data, |d| read_utf8_string(d)).unwrap(), "");

        // UTF8 invalid bytes
        let data = hex_to_bytes("0C 02 C3 28");
        assert!(decode(&data, |d| read_utf8_string(d)).is_err());

        // Visible "World"
        let data = hex_to_bytes("1A 05 57 6F 72 6C 64");
        assert_eq!(decode(&data, |d| read_visible_string(d)).unwrap(), "World");

        // Visible with ASCII space/symbols "AB !@#"
        let data = hex_to_bytes("1A 06 41 42 20 21 40 23");
        assert_eq!(decode(&data, |d| read_visible_string(d)).unwrap(), "AB !@#");
    }

    #[test]
    fn test_read_utc_time_cases() {
        // 2023-05-12 14:39:45Z => "230512143945Z"
        let data = hex_to_bytes("17 0D 32 33 30 35 31 32 31 34 33 39 34 35 5A");
        let t = decode(&data, |d| read_utc_time(d)).unwrap();
        assert_eq!(t.year, 2023);
        assert_eq!(t.month, 5);
        assert_eq!(t.day, 12);
        assert_eq!(t.hour, 14);
        assert_eq!(t.minute, 39);
        assert_eq!(t.second, Some(45));
        assert!(t.offset.is_none());

        // with negative offset: "...-0500"
        let data = hex_to_bytes("17 11 32 33 30 35 31 32 31 34 33 39 34 35 2D 30 35 30 30");
        let t = decode(&data, |d| read_utc_time(d)).unwrap();
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
        let t = decode(&data, |d| read_utc_time(d)).unwrap();
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
        let t = decode(&data, |d| read_generalized_time(d)).unwrap();
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
        let t = decode(&data, |d| read_generalized_time(d)).unwrap();
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