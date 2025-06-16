use std::fmt::Debug;
use std::str;
use thiserror::Error;
use crate::Asn1Tag;

/// ASN.1 type identifiers as defined in ITU-T X.680.
pub mod asn1_type {
    pub const BOOLEAN: u32 = 0x01;
    pub const INTEGER: u32 = 0x02;
    pub const BIT_STRING: u32 = 0x03;
    pub const OCTET_STRING: u32 = 0x04;
    pub const NULL: u32 = 0x05;
    pub const OBJECT_IDENTIFIER: u32 = 0x06;
    pub const OBJECT_DESCRIPTOR: u32 = 0x07;
    pub const EXTERNAL: u32 = 0x08;
    pub const REAL: u32 = 0x09;
    pub const ENUMERATED: u32 = 0x0A;
    pub const EMBEDDED_PDV: u32 = 0x0B;
    pub const UTF8_STRING: u32 = 0x0C;
    pub const RELATIVE_OID: u32 = 0x0D;
    pub const TIME: u32 = 0x0E;
    pub const SEQUENCE: u32 = 0x10;
    pub const SET: u32 = 0x11;
    pub const NUMERIC_STRING: u32 = 0x12;
    pub const PRINTABLE_STRING: u32 = 0x13;
    pub const TELETEX_STRING: u32 = 0x14;
    pub const VIDEOTEX_STRING: u32 = 0x15;
    pub const IA5_STRING: u32 = 0x16;
    pub const UTC_TIME: u32 = 0x17;
    pub const GENERALIZED_TIME: u32 = 0x18;
    pub const GRAPHIC_STRING: u32 = 0x19;
    pub const VISIBLE_STRING: u32 = 0x1A;
    pub const GENERAL_STRING: u32 = 0x1B;
    pub const UNIVERSAL_STRING: u32 = 0x1C;
    pub const CHARACTER_STRING: u32 = 0x1D;
    pub const BMP_STRING: u32 = 0x1E;
    pub const DATE: u32 = 0x1F;
    pub const TIME_OF_DAY: u32 = 0x20;
    pub const DATE_TIME: u32 = 0x21;
    pub const DURATION: u32 = 0x22;
}

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
            return Err(Asn1DecoderError::new("Offset must be <= `end_offset`"));
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
    pub fn advance_with_tag<T, F>(&mut self, tag_number: u32, tag_class: u8, block: F) -> Result<T, Asn1DecoderError>
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
                // Check end of content `0x00 0x00` on infinite length
                let end_bytes = self.read_bytes(2)?;
                if end_bytes != [0x00, 0x00] {
                    return self.fail("Infinite length object must be finished with `0x00 0x00`");
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
        let first_byte = self.read_byte()? as u32;
        let tag_class_and_constructed = (first_byte & 0xE0) as u8; // Class and constructed bits
        let tag_number = first_byte & 0x1F;

        if tag_number == 0x1F {
            // Multibyte tag: Read until MSB is 0
            let mut value = 0u32;
            loop {
                if self.offset >= self.end_offset {
                    return self.fail("Unexpected end of data in tag");
                }

                let next_byte = self.read_byte()? as u32;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_read_boolean() {
        // Test true
        let data = [0x01, 0x01, 0xFF];
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        let result = read_boolean(&mut decoder).unwrap();
        assert_eq!(result, true);

        // Test false
        let data = [0x01, 0x01, 0x00];
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        let result = read_boolean(&mut decoder).unwrap();
        assert_eq!(result, false);
    }

    #[test]
    fn test_read_integer() {
        // Test positive
        let data = [0x02, 0x01, 0x7F];
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        let result = read_int(&mut decoder).unwrap();
        assert_eq!(result, 127);

        // Test positive multi-byte
        let data = [0x02, 0x02, 0x01, 0x00];
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        let result = read_int(&mut decoder).unwrap();
        assert_eq!(result, 256);

        // Test negative
        let data = [0x02, 0x01, 0x80];
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        let result = read_int(&mut decoder).unwrap();
        assert_eq!(result, -128);
    }

    #[test]
    fn test_read_octet_string() {
        let data = [0x04, 0x03, 0x01, 0x02, 0x03];
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        let result = read_octet_string(&mut decoder).unwrap();
        assert_eq!(result, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_read_utf8_string() {
        let data = [0x0C, 0x04, 0x74, 0x65, 0x73, 0x74]; // "test"
        let mut decoder = Asn1Decoder::new(&data).unwrap();
        let result = read_utf8_string(&mut decoder).unwrap();
        assert_eq!(result, "test");
    }
}