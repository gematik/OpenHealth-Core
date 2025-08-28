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

use thiserror::Error;

/// Error type for ASN.1 operations
#[derive(Error, Debug)]
pub enum Asn1Error {
    #[error("Encoding error: {0}")]
    EncodingError(String),

    #[error("Decoding error: {0}")]
    DecodingError(String),

    #[error("Invalid tag: {0}")]
    InvalidTag(String),

    #[error("Invalid length: {0}")]
    InvalidLength(String),

    #[error("Invalid format: {0}")]
    InvalidFormat(String),

    #[error("Unexpected error: {0}")]
    UnexpectedError(String),
}

/// Result type for ASN.1 operations
pub type Result<T> = std::result::Result<T, Asn1Error>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error as _;

    #[test]
    fn display_messages_are_correct() {
        let e1 = Asn1Error::EncodingError("oops".to_string());
        assert_eq!(e1.to_string(), "Encoding error: oops");

        let e2 = Asn1Error::DecodingError("bad input".to_string());
        assert_eq!(e2.to_string(), "Decoding error: bad input");

        let e3 = Asn1Error::InvalidTag("tag 0x1F".to_string());
        assert_eq!(e3.to_string(), "Invalid tag: tag 0x1F");

        let e4 = Asn1Error::InvalidLength("len 999999".to_string());
        assert_eq!(e4.to_string(), "Invalid length: len 999999");

        let e5 = Asn1Error::InvalidFormat("not DER".to_string());
        assert_eq!(e5.to_string(), "Invalid format: not DER");

        let e6 = Asn1Error::UnexpectedError("boom".to_string());
        assert_eq!(e6.to_string(), "Unexpected error: boom");
    }

    #[test]
    fn error_source_is_none_for_all_variants() {
        let errs: Vec<Asn1Error> = vec![
            Asn1Error::EncodingError("e".into()),
            Asn1Error::DecodingError("e".into()),
            Asn1Error::InvalidTag("e".into()),
            Asn1Error::InvalidLength("e".into()),
            Asn1Error::InvalidFormat("e".into()),
            Asn1Error::UnexpectedError("e".into()),
        ];
        for e in errs {
            assert!(std::error::Error::source(&e).is_none());
        }
    }

    #[test]
    fn result_alias_compiles_and_propagates() {
        fn failing() -> Result<()> {
            Err(Asn1Error::InvalidFormat("x".into()))
        }
        let err = failing().unwrap_err();
        assert!(matches!(err, Asn1Error::InvalidFormat(_)));
        assert_eq!(err.to_string(), "Invalid format: x");
    }
}
