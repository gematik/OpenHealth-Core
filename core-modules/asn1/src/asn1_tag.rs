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
    Boolean = 0x01,
    Integer = 0x02,
    BitString = 0x03,
    OctetString = 0x04,
    Null = 0x05,
    ObjectIdentifier = 0x06,
    ObjectDescriptor = 0x07,
    External = 0x08,
    Real = 0x09,
    Enumerated = 0x0A,
    EmbeddedPdv = 0x0B,
    Utf8String = 0x0C,
    RelativeOid = 0x0D,
    Time = 0x0E,
    Sequence = 0x10,
    Set = 0x11,
    NumericString = 0x12,
    PrintableString = 0x13,
    TeletexString = 0x14,
    VideotexString = 0x15,
    Ia5String = 0x16,
    UtcTime = 0x17,
    GeneralizedTime = 0x18,
    GraphicString = 0x19,
    VisibleString = 0x1A,
    GeneralString = 0x1B,
    UniversalString = 0x1C,
    CharacterString = 0x1D,
    BmpString = 0x1E,
    Date = 0x1F,
    TimeOfDay = 0x20,
    DateTime = 0x21,
    Duration = 0x22,
}

impl UniversalTag {
    #[inline]
    pub const fn number(self) -> u32 {
        self as u32
    }

    #[inline]
    pub const fn primitive(self) -> Asn1Id {
        Asn1Id::uni(self.number())
    }

    #[inline]
    pub const fn constructed(self) -> Asn1Id {
        Asn1Id::uni(self.number()).constructed()
    }

    #[inline]
    pub const fn from_number(n: u32) -> Option<Self> {
        Some(match n {
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
            _ => return None,
        })
    }
}

impl From<UniversalTag> for u8 {
    #[inline]
    fn from(tag: UniversalTag) -> u8 {
        tag as u8
    }
}

impl TryFrom<u8> for UniversalTag {
    type Error = u8;

    #[inline]
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        UniversalTag::from_number(value as u32).ok_or(value)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Asn1Id {
    pub class: Asn1Class,
    pub form: Asn1Form,
    pub number: u32,
}

impl Asn1Id {
    pub const fn new(class: Asn1Class, form: Asn1Form, number: u32) -> Self {
        Self {
            class,
            form,
            number,
        }
    }

    pub const fn uni(n: u32) -> Self {
        Self::new(Asn1Class::Universal, Asn1Form::Primitive, n)
    }
    pub const fn app(n: u32) -> Self {
        Self::new(Asn1Class::Application, Asn1Form::Primitive, n)
    }
    pub const fn ctx(n: u32) -> Self {
        Self::new(Asn1Class::ContextSpecific, Asn1Form::Primitive, n)
    }
    pub const fn prv(n: u32) -> Self {
        Self::new(Asn1Class::Private, Asn1Form::Primitive, n)
    }

    pub const fn primitive(mut self) -> Self {
        self.form = Asn1Form::Primitive;
        self
    }
    pub const fn constructed(mut self) -> Self {
        self.form = Asn1Form::Constructed;
        self
    }

    pub fn as_universal(&self) -> Option<UniversalTag> {
        if self.class == Asn1Class::Universal {
            UniversalTag::from_number(self.number)
        } else {
            None
        }
    }
}

/// Extension methods to build [`Asn1Id`] values directly from tag numbers.
pub trait TagNumberExt {
    fn uni_tag(self) -> Asn1Id;
    fn app_tag(self) -> Asn1Id;
    fn ctx_tag(self) -> Asn1Id;
    fn prv_tag(self) -> Asn1Id;
}

impl TagNumberExt for u8 {
    #[inline]
    fn uni_tag(self) -> Asn1Id {
        (self as u32).uni_tag()
    }
    #[inline]
    fn app_tag(self) -> Asn1Id {
        (self as u32).app_tag()
    }
    #[inline]
    fn ctx_tag(self) -> Asn1Id {
        (self as u32).ctx_tag()
    }
    #[inline]
    fn prv_tag(self) -> Asn1Id {
        (self as u32).prv_tag()
    }
}

impl TagNumberExt for u16 {
    #[inline]
    fn uni_tag(self) -> Asn1Id {
        (self as u32).uni_tag()
    }
    #[inline]
    fn app_tag(self) -> Asn1Id {
        (self as u32).app_tag()
    }
    #[inline]
    fn ctx_tag(self) -> Asn1Id {
        (self as u32).ctx_tag()
    }
    #[inline]
    fn prv_tag(self) -> Asn1Id {
        (self as u32).prv_tag()
    }
}

impl TagNumberExt for u32 {
    #[inline]
    fn uni_tag(self) -> Asn1Id {
        Asn1Id::uni(self)
    }
    #[inline]
    fn app_tag(self) -> Asn1Id {
        Asn1Id::app(self)
    }
    #[inline]
    fn ctx_tag(self) -> Asn1Id {
        Asn1Id::ctx(self)
    }
    #[inline]
    fn prv_tag(self) -> Asn1Id {
        Asn1Id::prv(self)
    }
}

/// Primitive/Constructed bit (PC) in the identifier octet
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Asn1Form {
    Primitive = 0x00,
    Constructed = 0x20,
}

impl From<Asn1Form> for u8 {
    #[inline]
    fn from(pc: Asn1Form) -> u8 {
        pc as u8
    }
}

/// Tag class bits in the identifier octet
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Asn1Class {
    Universal = 0x00,
    Application = 0x40,
    ContextSpecific = 0x80,
    Private = 0xC0,
}

impl From<Asn1Class> for u8 {
    #[inline]
    fn from(c: Asn1Class) -> u8 {
        c as u8
    }
}

// Allow ergonomic `Class | Pc` combinations that yield the encoded class byte
impl core::ops::BitOr<Asn1Form> for Asn1Class {
    type Output = u8;
    #[inline]
    fn bitor(self, rhs: Asn1Form) -> Self::Output {
        (self as u8) | (rhs as u8)
    }
}
impl core::ops::BitOr<Asn1Class> for Asn1Form {
    type Output = u8;
    #[inline]
    fn bitor(self, rhs: Asn1Class) -> Self::Output {
        (self as u8) | (rhs as u8)
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
            // u8 -> tag
            let from_b = UniversalTag::try_from(*byte).unwrap();
            assert_eq!(&from_b, tag, "try_from({byte:02X}) should map to {:?}", tag);
            // tag -> u8
            let to_b: u8 = (*tag).into();
            assert_eq!(to_b, *byte, "into() should produce {byte:02X}");
        }
    }

    #[test]
    fn invalid_value_fails() {
        for b in [0x00u8, 0x0F, 0x23, 0xFE, 0xFF] {
            assert!(UniversalTag::try_from(b).is_err());
        }
    }
}
