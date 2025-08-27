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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagClass {
    Universal,
    Application,
    ContextSpecific,
    Private,
}

impl TagClass {
    #[inline]
    pub const fn to_bits(self) -> u8 {
        match self {
            TagClass::Universal => 0x00,
            TagClass::Application => 0x40,
            TagClass::ContextSpecific => 0x80,
            TagClass::Private => 0xC0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asn1Tag {
    pub class: TagClass,
    pub constructed: bool,
    pub asn1_type: Asn1Type,
}

impl Asn1Tag {
    /// Create a primitive tag.
    pub const fn new(class: TagClass, number: Asn1Type) -> Self {
        Self {
            class,
            constructed: false,
            asn1_type: number,
        }
    }


    /// Mark as constructed (or not) fluently.
    pub const fn with_constructed(mut self, constructed: bool) -> Self {
        self.constructed = constructed;
        self
    }

    /// First octet class/pc bits.
    #[inline]
    pub const fn pc_bits(&self) -> u8 {
        if self.constructed {
            0x20
        } else {
            0x00
        }
    }

    /// Encode this tag to bytes according to X.690 (high-tag-number form supported).
    pub fn to_bytes(self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4);
        let class_bits = self.class.to_bits();
        let pc = self.pc_bits();
        let number: u8 = u8::from(self.asn1_type);
        if number < 31 {
            out.push(class_bits | pc | number);
        } else {
            out.push(class_bits | pc | 0x1F);
            // base-128 big-endian with MSB as continuation
            let mut stack: [u8; 10] = [0; 10];
            let mut i = 0;
            let mut n: u8 = number;
            loop {
                stack[i] = n & 0x7F;
                i += 1;
                n >>= 7;
                if n == 0 {
                    break;
                }
            }
            // write in reverse with continuation bits
            for j in (0..i).rev() {
                let mut b = stack[j];
                if j != 0 {
                    b |= 0x80;
                }
                out.push(b);
            }
        }
        out
    }
}

impl fmt::Display for Asn1Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let class = match self.class {
            TagClass::Universal => "UNIVERSAL",
            TagClass::Application => "APPLICATION",
            TagClass::ContextSpecific => "CONTEXT_SPECIFIC",
            TagClass::Private => "PRIVATE",
        };
        write!(
            f,
            "Asn1Tag(class={}, constructed={}, number=0x{:x})",
            class, self.constructed, u8::from(self.asn1_type)
        )
    }
}

/// ASN.1 type identifiers as defined in ITU-T X.680 (strict enum form).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Asn1Type {
    Boolean             = 0x01,
    Integer             = 0x02,
    BitString           = 0x03,
    OctetString         = 0x04,
    Null                = 0x05,
    ObjectIdentifier    = 0x06,
    ObjectDescriptor    = 0x07,
    External            = 0x08,
    Real                = 0x09,
    Enumerated          = 0x0A,
    EmbeddedPdv         = 0x0B,
    Utf8String          = 0x0C,
    RelativeOid         = 0x0D,
    Time                = 0x0E,
    Sequence            = 0x10,
    Set                 = 0x11,
    NumericString       = 0x12,
    PrintableString     = 0x13,
    TeletexString       = 0x14,
    VideotexString      = 0x15,
    Ia5String           = 0x16,
    UtcTime             = 0x17,
    GeneralizedTime     = 0x18,
    GraphicString       = 0x19,
    VisibleString       = 0x1A,
    GeneralString       = 0x1B,
    UniversalString     = 0x1C,
    CharacterString     = 0x1D,
    BmpString           = 0x1E,
    Date                = 0x1F,
    TimeOfDay           = 0x20,
    DateTime            = 0x21,
    Duration            = 0x22,
}

impl TryFrom<u8> for Asn1Type {
    type Error = u8; // return the offending tag number for strict handling

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        let t = match value {
            0x01 => Self::Boolean,
            0x02 => Self::Integer,
            0x03 => Self::BitString,
            0x04 => Self::OctetString,
            0x05 => Self::Null,
            0x06 => Self::ObjectIdentifier,
            0x07 => Self::ObjectDescriptor,
            0x08 => Self::External,
            0x09 => Self::Real,
            0x0A => Self::Enumerated,
            0x0B => Self::EmbeddedPdv,
            0x0C => Self::Utf8String,
            0x0D => Self::RelativeOid,
            0x0E => Self::Time,
            0x10 => Self::Sequence,
            0x11 => Self::Set,
            0x12 => Self::NumericString,
            0x13 => Self::PrintableString,
            0x14 => Self::TeletexString,
            0x15 => Self::VideotexString,
            0x16 => Self::Ia5String,
            0x17 => Self::UtcTime,
            0x18 => Self::GeneralizedTime,
            0x19 => Self::GraphicString,
            0x1A => Self::VisibleString,
            0x1B => Self::GeneralString,
            0x1C => Self::UniversalString,
            0x1D => Self::CharacterString,
            0x1E => Self::BmpString,
            0x1F => Self::Date,
            0x20 => Self::TimeOfDay,
            0x21 => Self::DateTime,
            0x22 => Self::Duration,
            other => return Err(other),
        };
        Ok(t)
    }
}

impl From<Asn1Type> for u8 {
    #[inline]
    fn from(t: Asn1Type) -> Self { t as u8 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asn1_tag_display() {
        let tag = Asn1Tag::new(TagClass::Universal, Asn1Type::Sequence).with_constructed(false);
        assert_eq!(
            format!("{}", tag),
            "Asn1Tag(class=UNIVERSAL, constructed=false, number=0x10)"
        );
    }

    #[test]
    fn test_asn1_tag_equality() {
        let tag1 = Asn1Tag::new(TagClass::Universal, Asn1Type::Sequence);
        let tag2 = Asn1Tag::new(TagClass::Universal, Asn1Type::Sequence);
        let tag3 = Asn1Tag::new(TagClass::Universal, Asn1Type::Integer);
        assert_eq!(tag1, tag2);
        assert_ne!(tag1, tag3);
    }
}
