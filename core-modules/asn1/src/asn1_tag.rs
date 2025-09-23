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
}



impl core::fmt::Display for UniversalTag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:02X}", *self as u8)
    }
}

impl From<UniversalTag> for u8 {
    #[inline]
    fn from(t: UniversalTag) -> Self { t as u8 }
}

/// ASN.1 tag as defined in ITU-T X.680.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asn1Tag {
    pub tag_class: u8,
    pub tag_number: u32,
}

impl Asn1Tag {
    pub const CONSTRUCTED: u8 = 0x20;
    pub const APPLICATION: u8 = 0x40;
    pub const CONTEXT_SPECIFIC: u8 = 0x80;
    pub const PRIVATE: u8 = 0xC0;

    #[inline]
    pub const fn new(tag_class: u8, tag_number: u32) -> Self {
        Asn1Tag { tag_class, tag_number }
    }
}