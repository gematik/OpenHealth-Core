
pub mod asn1_tag;
pub mod asn1_encoder;
pub mod asn1_decoder;
mod error;
pub mod asn1_date_time;
pub mod asn1_object_identifier;

// Public re-exports
pub use asn1_tag::{Asn1Tag, tag_class, asn1_type};

pub use asn1_object_identifier::{read_object_identifier, write_object_identifier};
pub use error::{Asn1Error, Result};
pub use asn1_date_time::{Asn1UtcTime, Asn1GeneralizedTime};

pub use asn1_decoder::{
    Asn1Decoder, read_boolean, read_int, read_bit_string,
    read_octet_string, read_utf8_string, read_visible_string, Asn1DecoderError
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