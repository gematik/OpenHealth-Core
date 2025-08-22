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

use std::fmt;

/// ASN.1 tag structure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asn1Tag {
    pub tag_class: u8,
    pub tag_number: u8,
}

impl Asn1Tag {
    pub fn new(tag_class: u8, tag_number: u8) -> Self {
        Asn1Tag {
            tag_class,
            tag_number,
        }
    }
}

impl fmt::Display for Asn1Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Asn1Tag(tagClass=0x{:02x}, tagNumber=0x{:x})",
            self.tag_class, self.tag_number
        )
    }
}

/// ASN.1 tag class constants.
pub mod tag_class {
    pub const CONSTRUCTED: u8 = 0x20;
    pub const APPLICATION: u8 = 0x40;
    pub const CONTEXT_SPECIFIC: u8 = 0x80;
    pub const PRIVATE: u8 = 0xC0;
}

/// ASN.1 type identifiers as defined in ITU-T X.680.
pub mod asn1_type {
    pub const BOOLEAN: u8 = 0x01;
    pub const INTEGER: u8 = 0x02;
    pub const BIT_STRING: u8 = 0x03;
    pub const OCTET_STRING: u8 = 0x04;
    pub const NULL: u8 = 0x05;
    pub const OBJECT_IDENTIFIER: u8 = 0x06;
    pub const OBJECT_DESCRIPTOR: u8 = 0x07;
    pub const EXTERNAL: u8 = 0x08;
    pub const REAL: u8 = 0x09;
    pub const ENUMERATED: u8 = 0x0A;
    pub const EMBEDDED_PDV: u8 = 0x0B;
    pub const UTF8_STRING: u8 = 0x0C;
    pub const RELATIVE_OID: u8 = 0x0D;
    pub const TIME: u8 = 0x0E;
    pub const SEQUENCE: u8 = 0x10;
    pub const SET: u8 = 0x11;
    pub const NUMERIC_STRING: u8 = 0x12;
    pub const PRINTABLE_STRING: u8 = 0x13;
    pub const TELETEX_STRING: u8 = 0x14;
    pub const VIDEOTEX_STRING: u8 = 0x15;
    pub const IA5_STRING: u8 = 0x16;
    pub const UTC_TIME: u8 = 0x17;
    pub const GENERALIZED_TIME: u8 = 0x18;
    pub const GRAPHIC_STRING: u8 = 0x19;
    pub const VISIBLE_STRING: u8 = 0x1A;
    pub const GENERAL_STRING: u8 = 0x1B;
    pub const UNIVERSAL_STRING: u8 = 0x1C;
    pub const CHARACTER_STRING: u8 = 0x1D;
    pub const BMP_STRING: u8 = 0x1E;
    pub const DATE: u8 = 0x1F;
    pub const TIME_OF_DAY: u8 = 0x20;
    pub const DATE_TIME: u8 = 0x21;
    pub const DURATION: u8 = 0x22;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asn1_tag_display() {
        let tag = Asn1Tag::new(tag_class::CONTEXT_SPECIFIC, 5);
        assert_eq!(format!("{}", tag), "Asn1Tag(tagClass=0x80, tagNumber=0x5)");
    }

    #[test]
    fn test_asn1_tag_equality() {
        let tag1 = Asn1Tag::new(tag_class::CONTEXT_SPECIFIC, 5);
        let tag2 = Asn1Tag::new(tag_class::CONTEXT_SPECIFIC, 5);
        let tag3 = Asn1Tag::new(tag_class::APPLICATION, 5);

        assert_eq!(tag1, tag2);
        assert_ne!(tag1, tag3);
    }
}