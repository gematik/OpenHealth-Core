// SPDX-FileCopyrightText: Copyright 2025 - 2026 gematik GmbH
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

use crate::decoder::{Asn1Decoder, Asn1Length};
use crate::error::Asn1DecoderError;
use crate::tag::Asn1Class;

/// Extracts all context-specific values with the given tag number.
///
/// Indefinite-length values are rejected.
pub fn extract_context_values(data: &[u8], tag_number: u32) -> Result<Vec<Vec<u8>>, Asn1DecoderError> {
    Asn1Decoder::new(data).read(|scope| {
        let mut values = Vec::new();
        while scope.remaining_length() > 0 {
            let tag = scope.read_tag()?;
            let length = scope.read_length()?;
            let content_len = match length {
                Asn1Length::Definite(len) => len,
                Asn1Length::Indefinite => {
                    return Err(Asn1DecoderError::custom(
                        "indefinite length not supported in context-specific extraction",
                    ))
                }
            };
            let value = scope.read_bytes(content_len)?;
            if tag.class == Asn1Class::ContextSpecific && tag.number == tag_number {
                values.push(value);
            }
        }
        Ok(values)
    })
}

#[cfg(test)]
mod tests {
    use super::extract_context_values;
    use crate::error::Asn1DecoderError;

    fn hex_bytes(s: &str) -> Vec<u8> {
        s.split_ascii_whitespace().map(|b| u8::from_str_radix(b, 16).unwrap()).collect()
    }

    #[test]
    fn extract_context_values_filters_by_tag() {
        let data = hex_bytes("83 02 AA BB 5F 20 01 01 83 03 CC DD EE");
        let values = extract_context_values(&data, 3).unwrap();
        assert_eq!(values, vec![vec![0xAA, 0xBB], vec![0xCC, 0xDD, 0xEE]]);
    }

    #[test]
    fn extract_context_values_rejects_indefinite() {
        let data = hex_bytes("83 80 01 01 00 00");
        let err = extract_context_values(&data, 3).unwrap_err();
        assert!(matches!(err, Asn1DecoderError::Custom { .. }));
    }
}
