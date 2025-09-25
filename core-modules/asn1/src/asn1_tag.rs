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

/// ASN.1 type identifiers as defined in ITU-T X.680.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UniversalTag {
    Boolean            = 0x01,
    Integer            = 0x02,
    BitString          = 0x03,
    OctetString        = 0x04,
    Null               = 0x05,
    ObjectIdentifier   = 0x06,
    ObjectDescriptor   = 0x07,
    External           = 0x08,
    Real               = 0x09,
    Enumerated         = 0x0A,
    EmbeddedPdv        = 0x0B,
    Utf8String         = 0x0C,
    RelativeOid        = 0x0D,
    Time               = 0x0E,
    Sequence           = 0x10,
    Set                = 0x11,
    NumericString      = 0x12,
    PrintableString    = 0x13,
    TeletexString      = 0x14,
    VideotexString     = 0x15,
    Ia5String          = 0x16,
    UtcTime            = 0x17,
    GeneralizedTime    = 0x18,
    GraphicString      = 0x19,
    VisibleString      = 0x1A,
    GeneralString      = 0x1B,
    UniversalString    = 0x1C,
    CharacterString    = 0x1D,
    BmpString          = 0x1E,
    Date               = 0x1F,
    TimeOfDay          = 0x20,
    DateTime           = 0x21,
    Duration           = 0x22,
    /// Any unknown/unsupported universal tag number
    Unknown(u8),
}

impl From<UniversalTag> for u8 {
    #[inline]
    fn from(t: UniversalTag) -> Self {
        match t {
            UniversalTag::Unknown(x) => x,
            UniversalTag::Boolean => 0x01,
            UniversalTag::Integer => 0x02,
            UniversalTag::BitString => 0x03,
            UniversalTag::OctetString => 0x04,
            UniversalTag::Null => 0x05,
            UniversalTag::ObjectIdentifier => 0x06,
            UniversalTag::ObjectDescriptor => 0x07,
            UniversalTag::External => 0x08,
            UniversalTag::Real => 0x09,
            UniversalTag::Enumerated => 0x0A,
            UniversalTag::EmbeddedPdv => 0x0B,
            UniversalTag::Utf8String => 0x0C,
            UniversalTag::RelativeOid => 0x0D,
            UniversalTag::Time => 0x0E,
            UniversalTag::Sequence => 0x10,
            UniversalTag::Set => 0x11,
            UniversalTag::NumericString => 0x12,
            UniversalTag::PrintableString => 0x13,
            UniversalTag::TeletexString => 0x14,
            UniversalTag::VideotexString => 0x15,
            UniversalTag::Ia5String => 0x16,
            UniversalTag::UtcTime => 0x17,
            UniversalTag::GeneralizedTime => 0x18,
            UniversalTag::GraphicString => 0x19,
            UniversalTag::VisibleString => 0x1A,
            UniversalTag::GeneralString => 0x1B,
            UniversalTag::UniversalString => 0x1C,
            UniversalTag::CharacterString => 0x1D,
            UniversalTag::BmpString => 0x1E,
            UniversalTag::Date => 0x1F,
            UniversalTag::TimeOfDay => 0x20,
            UniversalTag::DateTime => 0x21,
            UniversalTag::Duration => 0x22,
        }
    }
}

impl From<u8> for UniversalTag {
    #[inline]
    fn from(v: u8) -> Self {
        use UniversalTag::*;
        match v {
            0x01 => Boolean,
            0x02 => Integer,
            0x03 => BitString,
            0x04 => OctetString,
            0x05 => Null,
            0x06 => ObjectIdentifier,
            0x07 => ObjectDescriptor,
            0x08 => External,
            0x09 => Real,
            0x0A => Enumerated,
            0x0B => EmbeddedPdv,
            0x0C => Utf8String,
            0x0D => RelativeOid,
            0x0E => Time,
            0x10 => Sequence,
            0x11 => Set,
            0x12 => NumericString,
            0x13 => PrintableString,
            0x14 => TeletexString,
            0x15 => VideotexString,
            0x16 => Ia5String,
            0x17 => UtcTime,
            0x18 => GeneralizedTime,
            0x19 => GraphicString,
            0x1A => VisibleString,
            0x1B => GeneralString,
            0x1C => UniversalString,
            0x1D => CharacterString,
            0x1E => BmpString,
            0x1F => Date,
            0x20 => TimeOfDay,
            0x21 => DateTime,
            0x22 => Duration,
            other => Unknown(other),
        }
    }
}


/// ASN.1 tag as defined in ITU-T X.680.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asn1Tag {
    pub tag_class: u8,
    pub tag_number: u32,
}

/// Primitive/Constructed bit (PC) in the identifier octet
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Asn1Form {
    Primitive   = 0x00,
    Constructed = 0x20,
}

impl From<Asn1Form> for u8 {
    #[inline]
    fn from(pc: Asn1Form) -> u8 { pc as u8 }
}

/// Tag class bits in the identifier octet
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Asn1Class {
    Universal       = 0x00,
    Application     = 0x40,
    ContextSpecific = 0x80,
    Private         = 0xC0,
}

impl From<Asn1Class> for u8 {
    #[inline]
    fn from(c: Asn1Class) -> u8 { c as u8 }
}

// Allow ergonomic `Class | Pc` combinations that yield the encoded class byte
impl core::ops::BitOr<Asn1Form> for Asn1Class {
    type Output = u8;
    #[inline]
    fn bitor(self, rhs: Asn1Form) -> Self::Output { (self as u8) | (rhs as u8) }
}
impl core::ops::BitOr<Asn1Class> for Asn1Form {
    type Output = u8;
    #[inline]
    fn bitor(self, rhs: Asn1Class) -> Self::Output { (self as u8) | (rhs as u8) }
}

impl Asn1Tag {
    pub const CONSTRUCTED: Asn1Form = Asn1Form::Constructed;
    pub const APPLICATION: Asn1Class = Asn1Class::Application;
    pub const CONTEXT_SPECIFIC: Asn1Class = Asn1Class::ContextSpecific;
    pub const PRIVATE: Asn1Class = Asn1Class::Private;

    #[inline]
    pub const fn new(tag_class: u8, tag_number: u32) -> Self {
        Asn1Tag { tag_class, tag_number }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_tags_roundtrip() {
        let cases: &[(u8, UniversalTag)] = &[
            (0x01, UniversalTag::Boolean),
            (0x02, UniversalTag::Integer),
            (0x04, UniversalTag::OctetString),
            (0x06, UniversalTag::ObjectIdentifier),
            (0x0C, UniversalTag::Utf8String),
            (0x10, UniversalTag::Sequence),
            (0x11, UniversalTag::Set),
            (0x17, UniversalTag::UtcTime),
            (0x18, UniversalTag::GeneralizedTime),
        ];
        for (byte, tag) in cases {
            // u8 -> enum
            let from_b = UniversalTag::from(*byte);
            assert_eq!(&from_b, tag, "from({byte:02X}) should map to {:?}", tag);
            // enum -> u8
            let to_b: u8 = (*tag).into();
            assert_eq!(to_b, *byte, "into() should produce {byte:02X}");
        }
    }

    #[test]
    fn unknown_is_preserved_both_ways() {
        for b in [0x00u8, 0x0F, 0x12, 0x1F, 0x23, 0xFE, 0xFF] {
            let e = UniversalTag::from(b);
            match e {
                UniversalTag::Unknown(x) => assert_eq!(x, b),
                _ => { }
            }
            let back: u8 = e.into();
            assert_eq!(back, b, "roundtrip must preserve the original byte");
        }
    }
}