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

pub mod asn1_decoder {
    pub use asn1::decoder::{Asn1Decoder, ParserScope};
}

pub mod asn1_encoder {
    pub use asn1::encoder::{encode, WriterScope};
}

pub mod asn1_object_identifier {
    use asn1::encoder::{Result, WriterScope};

    pub fn write_object_identifier(scope: &mut WriterScope, oid: &str) -> Result<()> {
        scope.write_object_identifier(oid)
    }
}

pub use asn1::decoder::Asn1DecoderError as Asn1Error;
pub use asn1::tag::Asn1Class as TagClass;
use asn1::tag::{Asn1Form, Asn1Id, UniversalTag};

/// Builder helper mirroring the original Kotlin convenience API.
pub struct Asn1Tag(Asn1Id);

impl Asn1Tag {
    pub fn new(class: TagClass, number: u32) -> Self {
        Self(Asn1Id::new(class, Asn1Form::Primitive, number))
    }

    pub fn with_constructed(mut self, constructed: bool) -> Self {
        self.0 = if constructed { self.0.constructed() } else { self.0.primitive() };
        self
    }
}

impl From<Asn1Tag> for Asn1Id {
    fn from(value: Asn1Tag) -> Self {
        value.0
    }
}

pub mod asn1_type {
    pub const SET: u32 = asn1::tag::UniversalTag::Set as u32;
    pub const SEQUENCE: u32 = asn1::tag::UniversalTag::Sequence as u32;
}

pub fn read_int(scope: &mut asn1::decoder::ParserScope<'_>) -> Result<i32, asn1::decoder::Asn1DecoderError> {
    scope.read_int_tagged()
}
