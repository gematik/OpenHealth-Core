use std::panic::panic_any;
use crate::asn1_tag::{asn1_type, Asn1Tag};
/// Exception class for ASN.1 decoding errors.
#[derive(Debug)]
pub struct Asn1DecoderError {
    pub message: String,
}

impl Asn1DecoderError {
    pub fn new(msg: String) -> Self {
        Self { message: msg }
    }
}

/// Constructs an `Asn1Decoder` from the given data.
/// The data slice will not be copied!
pub struct Asn1Decoder<'a> {
    data: &'a [u8],
}

/// [ParserScope] implements the basic parsing functionality.
///
/// Important:
/// [ParserScope] is treated as a mutable object throughout the entire time of calling [read].
pub struct ParserScope<'a> {
    data: &'a [u8],
    offset: usize,
    end_offset: usize,
}

impl<'a> ParserScope<'a> {
    /// Throws an `Asn1DecoderError` with the result of calling `message`.
    #[inline]
    pub fn fail(&self, message: impl FnOnce() -> String) -> ! {
        panic_any(Asn1DecoderError::new(message()))
    }

    /// Throws an `Asn1DecoderError` if `value` is false with the result of calling `message`.
    #[inline]
    pub fn check(&self, value: bool, message: impl FnOnce() -> String) {
        if !value {
            self.fail(message)
        }
    }

    #[inline]
    pub fn remaining_length(&self) -> usize {
        self.end_offset - self.offset
    }

    /// Advances the parser with the given tag and executes the provided block.
    /// Throws an `Asn1DecoderError` if the tag does not match.
    pub fn advance_with_tag<T>(
        &mut self,
        tag_number: u8,
        tag_class: u8,
        mut block: impl FnMut(&mut ParserScope<'a>) -> T,
    ) -> T {
        let tag = self.read_tag();
        if tag.tag_number != (tag_number as u32) || tag.tag_class != tag_class {
            self.fail(|| {
                format!(
                    "Expected tag `Asn1Tag(tagClass=0x{:X}, tagNumber=0x{:X})` but got `Asn1Tag(tagClass=0x{:X}, tagNumber=0x{:X})`",
                    tag_class, tag_number, tag.tag_class, tag.tag_number
                )
            });
        }
        let length = self.read_length();
        let is_infinite = length == -1;

        let original_end = self.end_offset;

        if !is_infinite {
            let len = length as usize;
            self.end_offset = self.offset + len;
        } else {
            self.end_offset = usize::MAX;
        }

        let result = block(self);

        if !is_infinite {
            if self.end_offset != self.offset {
                self.fail(|| "Unparsed bytes remaining".to_string());
            }
        } else {
            let end = self.read_bytes(2);
            if end != [0x00, 0x00] {
                self.fail(|| "Infinite length object must be finished with `0x00 0x00`".to_string());
            }
        }

        self.end_offset = original_end;
        result
    }

    /// Read one byte.
    #[inline]
    pub fn read_byte(&mut self) -> u8 {
        let b = self.data[self.offset];
        self.offset += 1;
        b
    }

    /// Read `length` bytes.
    pub fn read_bytes(&mut self, length: usize) -> Vec<u8> {
        self.check(length as isize >= 0, || {
            format!("Length must be >= `0`. Is `{}`", length)
        });
        let end = self.offset + length;
        let data = &self.data[self.offset..end];
        self.offset = end;
        data.to_vec()
    }

    /// Reads the next tag from the data, handling multi-byte tags.
    pub fn read_tag(&mut self) -> Asn1Tag {
        self.check(self.offset < self.end_offset, || "Unexpected end of data in tag".to_string());
        let first = (self.data[self.offset] as u32) & 0xFF;
        self.offset += 1;

        let tag_class_and_constructed = (first & 0xE0) as u8; // Class + constructed
        let tag_number_low = first & 0x1F;

        if tag_number_low == 0x1F {
            // High-tag-number form
            let mut value: u32 = 0;
            loop {
                if self.offset >= self.end_offset {
                    self.fail(|| "Unexpected end of data in tag".to_string());
                }
                let next = (self.data[self.offset] as u32) & 0xFF;
                self.offset += 1;
                value = (value << 7) | (next & 0x7F);
                if (next & 0x80) == 0 {
                    break;
                }
            }
            Asn1Tag::new(tag_class_and_constructed, value)
        } else {
            Asn1Tag::new(tag_class_and_constructed, tag_number_low as u32)
        }
    }

    /// Read the length. Returns `-1` for infinite length.
    pub fn read_length(&mut self) -> i32 {
        let length_byte = (self.read_byte() as i32) & 0xFF;
        if length_byte == 0x80 {
            -1
        } else if (length_byte & 0x80) == 0 {
            // short form
            length_byte
        } else {
            // long form
            let length_size = length_byte & 0x7F;
            self.read_int(length_size as usize, false)
        }
    }

    /// Read `length` bytes as an integer.
    pub fn read_int(&mut self, length: usize, signed: bool) -> i32 {
        self.check((1..=4).contains(&length), || {
            format!("Length must be in range of [1, 4]. Is `{}`", length)
        });
        let end = self.offset + length;
        let bytes = &self.data[self.offset..end];
        self.offset = end;

        let mut result = bytes[0] as i32;
        result = if signed && (result & 0x80) != 0 {
            result | -0x100 // sign extend
        } else {
            result & 0xFF
        };
        for i in 1..length {
            result = (result << 8) | ((bytes[i] as i32) & 0xFF);
        }
        result
    }

    /// Skip `length` bytes.
    #[inline]
    pub fn skip(&mut self, length: usize) {
        self.offset += length;
    }

    /// Skip to the `end_offset`.
    pub fn skip_to_end(&mut self) {
        self.check(self.end_offset != usize::MAX, || {
            "Can't skip bytes inside infinite length object".to_string()
        });
        self.offset = self.end_offset;
    }

    // ---------- High-level Leser wie in Kotlin ----------

    /// Read [Asn1Type.BOOLEAN].
    pub fn read_boolean(&mut self) -> bool {
        self.advance_with_tag(asn1_type::BOOLEAN, 0x00, |s| {
            s.read_byte() == 0xFF
        })
    }

    /// Read [Asn1Type.INTEGER].
    pub fn read_int_tagged(&mut self) -> i32 {
        self.advance_with_tag(asn1_type::INTEGER, 0x00, |s| {
            let len = s.remaining_length();
            s.read_int(len, true)
        })
    }

    /// Read [Asn1Type.BIT_STRING].
    pub fn read_bit_string(&mut self) -> Vec<u8> {
        self.advance_with_tag(asn1_type::BIT_STRING, 0x00, |s| {
            let unused_bits = s.read_byte() as i32;
            if !(0..=7).contains(&unused_bits) {
                s.fail(|| format!("Invalid unused bit count: {}", unused_bits));
            }
            let mut bit_string = s.read_bytes(s.remaining_length());
            if unused_bits == 0 {
                bit_string
            } else {
                // maskiere die ungenutzten Bits im letzten Byte
                let last = *bit_string.last().unwrap();
                let mask = (((0xFFu16 << unused_bits) & 0xFF) as u8) & 0xFF;
                bit_string.pop();
                bit_string.push(last & mask);
                bit_string
            }
        })
    }

    /// Read [Asn1Type.UTF8_STRING].
    pub fn read_utf8_string(&mut self) -> String {
        self.advance_with_tag(asn1_type::UTF8_STRING, 0x00, |s| {
            let bytes = s.read_bytes(s.remaining_length());
            String::from_utf8(bytes).unwrap_or_else(|_| {
                s.fail(|| "Malformed UTF-8 string".to_string());
            })
        })
    }

    /// Read [Asn1Type.VISIBLE_STRING].
    pub fn read_visible_string(&mut self) -> String {
        self.advance_with_tag(asn1_type::VISIBLE_STRING, 0x00, |s| {
            let bytes = s.read_bytes(s.remaining_length());
            String::from_utf8(bytes).unwrap_or_else(|_| {
                s.fail(|| "Malformed UTF-8 string".to_string());
            })
        })
    }

    /// Read [Asn1Type.OCTET_STRING].
    pub fn read_octet_string(&mut self) -> Vec<u8> {
        self.advance_with_tag(asn1_type::OCTET_STRING, 0x00, |s| {
            s.read_bytes(s.remaining_length())
        })
    }

    /// Read [Asn1Type.OBJECT_IDENTIFIER].
    pub fn read_object_identifier(&mut self) -> String {
        self.advance_with_tag(asn1_type::OBJECT_IDENTIFIER, 0x00, |s| {
            let bytes = s.read_bytes(s.remaining_length());
            if bytes.is_empty() {
                s.fail(|| "Encoded OID cannot be empty".to_string());
            }

            let first_byte = (bytes[0] as i32) & 0xFF;
            let first = first_byte / 40;
            let second = first_byte % 40;

            let mut parts: Vec<i32> = Vec::new();
            parts.push(first);
            parts.push(second);

            // Decode the remaining bytes (base-128)
            let mut value: i32 = 0;
            for b in &bytes[1..] {
                let byte = (*b as i32) & 0xFF;
                value = (value << 7) | (byte & 0x7F);
                if (byte & 0x80) == 0 {
                    parts.push(value);
                    value = 0;
                }
            }
            if value != 0 {
                s.fail(|| "Invalid OID encoding: unfinished encoding".to_string());
            }

            parts.iter().map(|v| v.to_string()).collect::<Vec<_>>().join(".")
        })
    }
}

impl<'a> Asn1Decoder<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        assert!(!data.is_empty(), "Data must not be empty");
        Self { data }
    }

    /// Reads the data using the provided `block` and returns the result.
    pub fn read<T>(&self, mut block: impl FnMut(&mut ParserScope<'a>) -> T) -> T {
        let mut scope = ParserScope {
            data: self.data,
            offset: 0,
            end_offset: self.data.len(),
        };
        block(&mut scope)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::asn1_tag::Asn1Tag;
    use crate::asn1_date_time::{Asn1Offset, Asn1UtcTime, Asn1GeneralizedTime};
    use std::panic::catch_unwind;

    fn hex_bytes(s: &str) -> Vec<u8> {
        s.split_whitespace()
            .filter(|p| !p.is_empty())
            .map(|p| u8::from_str_radix(p, 16).expect("hex"))
            .collect()
    }

    #[test]
    fn advance_with_tag() {
        let data = hex_bytes("30 0A 04 03 66 6F 6F 04 03 62 61 72");
        let parser = Asn1Decoder::new(&data);
        let result: Vec<String> = parser.read(|s| {
            s.advance_with_tag(0x10, Asn1Tag::CONSTRUCTED, |s| {
                let mut out = Vec::new();
                s.advance_with_tag(0x04, 0x00, |s| {
                    let v = String::from_utf8(s.read_bytes(3)).unwrap();
                    out.push(v);
                });
                s.advance_with_tag(0x04, 0x00, |s| {
                    let v = String::from_utf8(s.read_bytes(3)).unwrap();
                    out.push(v);
                });
                out
            })
        });
        assert_eq!(result, vec!["foo".to_string(), "bar".to_string()]);
    }

    #[test]
    fn advance_with_tag_infinite_length() {
        let data = hex_bytes("30 80 04 03 66 6F 6F 04 03 62 61 72 00 00");
        let parser = Asn1Decoder::new(&data);
        let result: Vec<String> = parser.read(|s| {
            s.advance_with_tag(0x10, Asn1Tag::CONSTRUCTED, |s| {
                let mut out = Vec::new();
                s.advance_with_tag(0x04, 0x00, |s| {
                    let v = String::from_utf8(s.read_bytes(3)).unwrap();
                    out.push(v);
                });
                s.advance_with_tag(0x04, 0x00, |s| {
                    let v = String::from_utf8(s.read_bytes(3)).unwrap();
                    out.push(v);
                });
                out
            })
        });
        assert_eq!(result, vec!["foo".to_string(), "bar".to_string()]);
    }

    #[test]
    fn advance_with_tag_unfinished_parsing() {
        let data = hex_bytes("30 80 04 03 66 6F 6F 04 03 62 61 72 00 00");
        let parser = Asn1Decoder::new(&data);
        let res = catch_unwind(|| {
            parser.read(|s| {
                s.advance_with_tag(0x30, 0x00, |s| {
                    s.advance_with_tag(0x04, 0x00, |s| {
                        let _ = s.read_bytes(3);
                    });
                })
            })
        });
        assert!(res.is_err());
    }

    #[test]
    fn advance_with_tag_skip_infinite() {
        let data = hex_bytes("30 80 04 03 66 6F 6F 04 03 62 61 72 00 00");
        let parser = Asn1Decoder::new(&data);
        let res = catch_unwind(|| {
            parser.read(|s| {
                s.advance_with_tag(0x30, 0x00, |s| {
                    s.advance_with_tag(0x04, 0x00, |s| {
                        let _ = s.read_bytes(3);
                    });
                    s.skip_to_end();
                })
            })
        });
        assert!(res.is_err());
    }

    #[test]
    fn read_boolean_true() {
        let data = hex_bytes("01 01 FF");
        let parser = Asn1Decoder::new(&data);
        let result = parser.read(|s| s.read_boolean());
        assert!(result);
    }

    #[test]
    fn read_boolean_false() {
        let data = hex_bytes("01 01 00");
        let parser = Asn1Decoder::new(&data);
        let result = parser.read(|s| s.read_boolean());
        assert!(!result);
    }

    #[test]
    fn read_integer() {
        let data = hex_bytes("02 01 7F");
        let parser = Asn1Decoder::new(&data);
        let result = parser.read(|s| s.read_int_tagged());
        assert_eq!(result, 127);
    }

    #[test]
    fn read_integer_negative() {
        let data = hex_bytes("02 01 EC");
        let parser = Asn1Decoder::new(&data);
        let result = parser.read(|s| s.read_int_tagged());
        assert_eq!(result, -20);
    }

    #[test]
    fn read_integer_boundary() {
        let data = hex_bytes("02 01 80");
        let parser = Asn1Decoder::new(&data);
        let result = parser.read(|s| s.read_int_tagged());
        assert_eq!(result, -128);
    }

    #[test]
    fn read_integer_multi_byte_length() {
        let data = hex_bytes("02 02 7F 7F");
        let parser = Asn1Decoder::new(&data);
        let result = parser.read(|s| s.read_int_tagged());
        assert_eq!(result, 32639);
    }

    #[test]
    fn read_bit_string_no_unused() {
        let data = hex_bytes("03 05 00 FF AA BB CC");
        let parser = Asn1Decoder::new(&data);
        let result = parser.read(|s| s.read_bit_string());
        assert_eq!(result, hex_bytes("FF AA BB CC"));
    }

    #[test]
    fn read_bit_string_with_unused() {
        let data = hex_bytes("03 05 03 FF AA BB FF");
        let parser = Asn1Decoder::new(&data);
        let result = parser.read(|s| s.read_bit_string());
        assert_eq!(result, hex_bytes("FF AA BB F8"));
    }

    #[test]
    fn read_bit_string_empty() {
        let data = hex_bytes("03 01 00");
        let parser = Asn1Decoder::new(&data);
        let result = parser.read(|s| s.read_bit_string());
        assert!(result.is_empty());
    }

    #[test]
    fn read_bit_string_invalid_unused() {
        let data = hex_bytes("03 04 08 FF AA BB CC");
        let parser = Asn1Decoder::new(&data);
        let res = catch_unwind(|| parser.read(|s| s.read_bit_string()));
        assert!(res.is_err());
    }

    #[test]
    fn read_bit_string_in_structure() {
        let data = hex_bytes("30 0C 03 04 00 FF AA BB 03 04 01 CC DD 00");
        let parser = Asn1Decoder::new(&data);
        let result: Vec<String> = parser.read(|s| {
            s.advance_with_tag(0x10, Asn1Tag::CONSTRUCTED, |s| {
                vec![
                    s.read_bit_string().iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "),
                    s.read_bit_string().iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" "),
                ]
            })
        });
        assert_eq!(result, vec!["FF AA BB".to_string(), "CC DD 00".to_string()]);
    }

    #[test]
    fn read_utf8_string() {
        let data = hex_bytes("0C 05 48 65 6C 6C 6F");
        let parser = Asn1Decoder::new(&data);
        let result = parser.read(|s| s.read_utf8_string());
        assert_eq!(result, "Hello");
    }

    #[test]
    fn read_utf8_string_empty() {
        let data = hex_bytes("0C 00");
        let parser = Asn1Decoder::new(&data);
        let result = parser.read(|s| s.read_utf8_string());
        assert_eq!(result, "");
    }

    #[test]
    fn read_utf8_string_invalid_data() {
        // Tag is OCTET STRING, decoder expects UTF8_STRING -> should error
        let data = hex_bytes("04 03 C3 28");
        let parser = Asn1Decoder::new(&data);
        let res = catch_unwind(|| parser.read(|s| s.read_utf8_string()));
        assert!(res.is_err());
    }

    #[test]
    fn read_visible_string() {
        let data = hex_bytes("1A 05 57 6F 72 6C 64");
        let parser = Asn1Decoder::new(&data);
        let result = parser.read(|s| s.read_visible_string());
        assert_eq!(result, "World");
    }

    #[test]
    fn read_visible_string_special_chars() {
        let data = hex_bytes("1A 06 41 42 20 21 40 23");
        let parser = Asn1Decoder::new(&data);
        let result = parser.read(|s| s.read_visible_string());
        assert_eq!(result, "AB !@#");
    }

    #[test]
    fn read_utc_time() {
        let data = hex_bytes("17 0D 32 33 30 35 31 32 31 34 33 39 34 35 5A");
        let parser = Asn1Decoder::new(&data);
        let t = parser.read(|s| s.read_utc_time());
        assert_eq!(t.year, 23);
        assert_eq!(t.month, 5);
        assert_eq!(t.day, 12);
        assert_eq!(t.hour, 14);
        assert_eq!(t.minute, 39);
        assert_eq!(t.second, Some(45));
        assert!(t.offset.is_none());
    }

    #[test]
    fn read_utc_time_negative_offset() {
        let data = hex_bytes("17 11 32 33 30 35 31 32 31 34 33 39 34 35 2D 30 35 30 30");
        let parser = Asn1Decoder::new(&data);
        let t = parser.read(|s| s.read_utc_time());
        assert_eq!(t.year, 23);
        assert_eq!(t.month, 5);
        assert_eq!(t.day, 12);
        assert_eq!(t.hour, 14);
        assert_eq!(t.minute, 39);
        assert_eq!(t.second, Some(45));
        match t.offset {
            Some(Asn1Offset::UtcOffset{hours, minutes}) => {
                assert_eq!(hours, -5);
                assert_eq!(minutes, 0);
            }
            _ => panic!("expected UtcOffset"),
        }
    }

    #[test]
    fn read_utc_time_missing_seconds() {
        let data = hex_bytes("17 0B 32 33 30 35 31 32 31 34 33 39 5A");
        let parser = Asn1Decoder::new(&data);
        let t = parser.read(|s| s.read_utc_time());
        assert_eq!(t.year, 23);
        assert_eq!(t.month, 5);
        assert_eq!(t.day, 12);
        assert_eq!(t.hour, 14);
        assert_eq!(t.minute, 39);
        assert_eq!(t.second, None);
        assert!(t.offset.is_none());
    }

    #[test]
    fn read_generalized_time() {
        let data = hex_bytes("18 12 32 30 32 33 30 35 31 32 31 34 33 39 34 35 2E 31 32 33 5A");
        let parser = Asn1Decoder::new(&data);
        let t = parser.read(|s| s.read_generalized_time());
        assert_eq!(t.year, 2023);
        assert_eq!(t.month, 5);
        assert_eq!(t.day, 12);
        assert_eq!(t.hour, 14);
        assert_eq!(t.minute, Some(39));
        assert_eq!(t.second, Some(45));
        assert_eq!(t.fraction_of_second, Some(123));
        assert!(t.offset.is_none());
    }

    #[test]
    fn read_generalized_time_no_fraction() {
        let data = hex_bytes("18 0D 32 30 32 33 30 35 31 32 31 34 33 39 5A");
        let parser = Asn1Decoder::new(&data);
        let t = parser.read(|s| s.read_generalized_time());
        assert_eq!(t.year, 2023);
        assert_eq!(t.month, 5);
        assert_eq!(t.day, 12);
        assert_eq!(t.hour, 14);
        assert_eq!(t.minute, Some(39));
        assert_eq!(t.second, None);
        assert_eq!(t.fraction_of_second, None);
        assert!(t.offset.is_none());
    }

    #[test]
    fn read_valid_simple_oid() {
        let data = hex_bytes("06 03 2A 03 04");
        let parser = Asn1Decoder::new(&data);
        let result = parser.read(|s| s.read_object_identifier());
        assert_eq!(result, "1.2.3.4");
    }

    #[test]
    fn read_valid_complex_oid() {
        let data = hex_bytes("06 05 55 04 06 82 03");
        let parser = Asn1Decoder::new(&data);
        let result = parser.read(|s| s.read_object_identifier());
        assert_eq!(result, "2.5.4.6.259");
    }

    #[test]
    fn read_empty_oid_throws() {
        let data = hex_bytes("06 00");
        let parser = Asn1Decoder::new(&data);
        let res = catch_unwind(|| parser.read(|s| s.read_object_identifier()));
        assert!(res.is_err());
    }

    #[test]
    fn read_single_byte_oid() {
        let data = hex_bytes("06 01 06");
        let parser = Asn1Decoder::new(&data);
        let result = parser.read(|s| s.read_object_identifier());
        assert_eq!(result, "0.6");
    }

    #[test]
    fn read_oid_with_high_value_bytes() {
        let data = hex_bytes("06 03 82 86 05");
        let parser = Asn1Decoder::new(&data);
        let result = parser.read(|s| s.read_object_identifier());
        assert_eq!(result, "3.10.773");
    }

    #[test]
    fn read_oid_overflow_in_intermediate_value() {
        let data = hex_bytes("06 04 2B 81 80 02");
        let parser = Asn1Decoder::new(&data);
        let result = parser.read(|s| s.read_object_identifier());
        assert_eq!(result, "1.3.16386");
    }

    #[test]
    fn read_oid_trailing_continuation_bit_throws() {
        let data = hex_bytes("06 02 2B 81");
        let parser = Asn1Decoder::new(&data);
        let res = catch_unwind(|| parser.read(|s| s.read_object_identifier()));
        assert!(res.is_err());
    }
}
