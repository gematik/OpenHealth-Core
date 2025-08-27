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
pub mod asn1_tag;
pub mod asn1_encoder;
pub mod asn1_decoder;
mod error;
pub mod asn1_date_time;
pub mod asn1_object_identifier;

// Public re-exports
pub use asn1_tag::{Asn1Tag};

pub use asn1_object_identifier::{read_object_identifier, write_object_identifier};
pub use error::{Asn1Error, Result};
pub use asn1_date_time::{Asn1UtcTime, Asn1GeneralizedTime};

pub use asn1_decoder::{
    Asn1Decoder, read_boolean, read_int, read_bit_string,
    read_octet_string, read_utf8_string
};

pub use asn1_encoder::{
    Asn1Encoder,
    write_tagged_object,
    write_boolean,
    write_int,
    write_bit_string,
    write_octet_string,
    write_utf8_string,
    write_tagged_object_with_inner_tag,
};

// Make modules public for direct access if needed
pub mod encoder {
    pub use crate::asn1_encoder::*;
}

pub mod decoder {
    pub use crate::asn1_decoder::*;
}

pub mod tag {
    pub use crate::asn1_tag::*;
}

pub mod date_time {
    pub use crate::asn1_date_time::*;
}

pub mod object_identifier {
    pub use crate::asn1_object_identifier::*;
}