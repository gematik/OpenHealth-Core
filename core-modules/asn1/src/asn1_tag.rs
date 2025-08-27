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

    /// Only class bits (primitive form)
    #[inline]
    pub const fn primitive(self) -> u8 { self.to_bits() }

    /// Class bits with constructed (PC) bit set
    #[inline]
    pub const fn constructed(self) -> u8 { self.to_bits() | 0x20 }

    /// Alias for to_bits(), for readability
    #[inline]
    pub const fn bits(self) -> u8 { self.to_bits() }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TagNumber {
    /// Universal tag with strong typing
    Universal(Asn1Type),
    /// Any other tag number (Application/Context/Private or unknown universal)
    Other(u32),
}

impl TagNumber {
    #[inline]
    pub const fn as_u32(self) -> u32 {
        match self {
            TagNumber::Universal(t) => t as u32,
            TagNumber::Other(n) => n,
        }
    }

    #[inline]
    pub const fn is_universal(self) -> bool {
        matches!(self, TagNumber::Universal(_))
    }

    #[inline]
    pub const fn as_universal(self) -> Option<Asn1Type> {
        match self { TagNumber::Universal(t) => Some(t), _ => None }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asn1Tag {
    pub class: TagClass,
    pub constructed: bool,
    pub number: TagNumber,
}

impl Asn1Tag {
    /// Create a primitive tag for a Universal type (readable and type‑safe)
    pub const fn new(class: TagClass, t: Asn1Type) -> Self {
        Self { class, constructed: false, number: TagNumber::Universal(t) }
    }

    /// Create a tag from a raw numeric tag number (for High‑Tag‑Number, context/application/private)
    pub const fn from_number(class: TagClass, constructed: bool, n: u32) -> Self {
        Self { class, constructed, number: TagNumber::Other(n) }
    }

    /// Mark as constructed (or not) fluently.
    pub const fn with_constructed(mut self, constructed: bool) -> Self {
        self.constructed = constructed;
        self
    }

    /// Class bits only (without PC and low‑5)
    #[inline]
    pub const fn class_bits(&self) -> u8 { self.class.to_bits() }

    /// PC bit only (without class and low‑5)
    #[inline]
    pub const fn pc_bits(&self) -> u8 { if self.constructed { 0x20 } else { 0x00 } }

    /// Returns the value to put into the low 5 bits of the first octet.
    /// If the numeric tag is >= 31, this returns 0x1F (high‑tag form).
    #[inline]
    pub const fn low5(&self) -> u8 {
        let n = self.number.as_u32();
        if n < 31 { n as u8 } else { 0x1F }
    }

    /// Returns the tag number as u32 (useful for encoder)
    #[inline]
    pub const fn number_u32(&self) -> u32 { self.number.as_u32() }

    /// Convenience: is this a Universal tag, and which one?
    #[inline]
    pub const fn as_universal(&self) -> Option<Asn1Type> { self.number.as_universal() }
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

impl From<Asn1Type> for u32 {
    #[inline]
    fn from(t: Asn1Type) -> Self { t as u32 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_asn1_tag_equality() {
        let tag1 = Asn1Tag::new(TagClass::Universal, Asn1Type::Sequence);
        let tag2 = Asn1Tag::new(TagClass::Universal, Asn1Type::Sequence);
        let tag3 = Asn1Tag::new(TagClass::Universal, Asn1Type::Integer);
        assert_eq!(tag1, tag2);
        assert_ne!(tag1, tag3);
    }

    #[test]
    fn test_asn1_tag_low5_and_number() {
        let seq = Asn1Tag::new(TagClass::Universal, Asn1Type::Sequence);
        assert_eq!(seq.low5(), Asn1Type::Sequence as u8);
        assert_eq!(seq.number_u32(), Asn1Type::Sequence as u32);
        assert!(seq.as_universal().is_some());

        let ctx_high = Asn1Tag::from_number(TagClass::ContextSpecific, false, 0x201);
        assert_eq!(ctx_high.low5(), 0x1F);
        assert_eq!(ctx_high.number_u32(), 0x201);
        assert!(ctx_high.as_universal().is_none());
    }
}
